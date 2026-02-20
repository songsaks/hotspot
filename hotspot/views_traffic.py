from django.shortcuts import render
from django.db.models import Q
from datetime import datetime, time, timedelta
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .models import Radacct
from .traffic_models import TrafficLog
from .utils import get_allowed_routers
from .log_parser import reverse_dns_cached, simplify_domain 
import re
import socket

# Excel Imports
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def parse_log_entry(url, method):
    """
    Parses a Squid/Proxy or Mikrotik log entry to extract meaningful fields.
    Handles 'got query from', 'got answer from', and standard URLs.
    """
    url_str = str(url or '').strip()
    method_str = str(method or '').strip()
    combined = url_str + " " + method_str

    log_type = 'Traffic'
    client_ip = None
    domain = None
    dst_ip = None
    port_name = '-'
    protocol = 'HTTP' # Default
    
    if not url_str and not method_str:
        return {'log_type': log_type, 'client_ip': None, 'domain': None, 'dst_ip': None, 'port_name': '-', 'protocol': '-'}

    # 1. Handle Mikrotik DNS style logs
    if 'got query from' in url_str:
        log_type = 'DNS Query'
        match = re.search(r'from ([\d\.]+):(\d+)', url_str)
        if match:
            client_ip = match.group(1)
            port_name = match.group(2)
            protocol = 'DNS'
    elif 'got answer from' in url_str:
        log_type = 'DNS Answer'
        match = re.search(r'from ([\d\.]+):(\d+)', url_str)
        if match:
            dst_ip = match.group(1)
            port_name = match.group(2)
            protocol = 'DNS'
    elif 'from' in url_str and '#' in url_str:
        # Format: "from 10.235.1.253: #1104899860 google.com. A"
        try:
             parts = url_str.split()
             if len(parts) >= 4:
                 candidate = parts[-2]
                 domain = candidate.rstrip('.')
                 log_type = 'DNS Query'
                 protocol = 'DNS'
                 # Find client IP
                 ip_match = re.search(r'from ([\d\.]+)', url_str)
                 if ip_match: client_ip = ip_match.group(1)
        except:
             pass

    # 2. Firewall Forward pattern (IP:PORT->IP:PORT)
    fw_match = re.search(r'([\d\.]+):(\d+)->([\d\.]+):(\d+)', combined)
    if fw_match:
        if not client_ip: client_ip = fw_match.group(1)
        if not dst_ip: dst_ip = fw_match.group(3)
        if port_name == '-': port_name = fw_match.group(4)
        log_type = 'FW'
        if 'proto UDP' in combined: protocol = 'UDP'
        elif 'proto TCP' in combined: protocol = 'TCP'

    # 3. Handle standard HTTP/HTTPS or CONNECT
    if method_str and 'CONNECT' in method_str.upper():
        log_type = 'HTTPS'
        protocol = 'HTTPS'
        domain = url_str.split(':')[0]
    elif '://' in url_str:
        try:
            parts = url_str.split('://')
            protocol = parts[0].upper()
            base = parts[1]
            domain_part = base.split('/')[0]
            domain = domain_part.split(':')[0]
        except:
            domain = url_str
    
    # Cleanup: If domain looks like an IP, move it to dst_ip
    if domain and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(domain)):
        if not dst_ip: dst_ip = domain
        domain = None

    return {
        'log_type': log_type,
        'client_ip': client_ip, 
        'domain': domain,
        'dst_ip': dst_ip,
        'port_name': port_name,
        'protocol': protocol
    }

def lookup_usernames_for_logs(logs_list):
    """
    Returns a dict: { source_ip: username }
    Finds the most recent user for each IP in the logs relative to the logs' time range.
    """
    if not logs_list:
        return {}
    
    source_ips = set()
    min_time = None
    
    for log in logs_list:
        # Check source_ip from DB
        if log.source_ip and log.source_ip.strip():
            source_ips.add(log.source_ip.strip())
            
        # Track min log time to optimize query
        if min_time is None or (log.log_time and log.log_time < min_time):
            min_time = log.log_time
        
        # ALSO check if we can parse a client_ip from the URL (mikrotik logs)
        parsed = parse_log_entry(log.url, log.method)
        if parsed['client_ip']:
            source_ips.add(parsed['client_ip'])
    
    if not source_ips:
        return {}
    
    # Define search window based on logs
    # Search sessions starting from (min_time - max_session_duration)
    # Default buffer 24 hours just to be safe
    from django.utils import timezone
    if min_time:
         # Ensure min_time is handled if it's naive/aware
         search_start_time = min_time - timedelta(days=1)
    else:
         search_start_time = timezone.now() - timedelta(days=30) 

    sessions = (
        Radacct.objects.using('default')
        .filter(framedipaddress__in=source_ips)
        # We relax the time filter to specific IPs found in logs
        # But we can assume sessions must have started *before* the newest log?
        # Actually, let's just look at sessions overlapping the log period or recently before.
        # Simplest: Get recent sessions relative to the Log data.
        .filter(acctstarttime__gte=search_start_time - timedelta(days=7)) # Look back a week from the oldest log
        .values('username', 'framedipaddress', 'acctstarttime')
        .order_by('framedipaddress', '-acctstarttime')
    )
    
    ip_to_user = {}
    for sess in sessions:
        ip = sess['framedipaddress']
        if ip:
            clean_ip = ip.strip()
            if clean_ip not in ip_to_user:
                ip_to_user[clean_ip] = sess['username']
            
    return ip_to_user

def enrich_logs(logs, resolve_dns=False):
    """
    Combines raw logs with parsed data (Domain, IP, User) for display.
    """
    enriched = []
    # Pre-fetch usernames
    username_map = lookup_usernames_for_logs(logs)
    
    for log in logs:
        parsed = parse_log_entry(log.url, log.method)
        src_ip = parsed['client_ip'] or log.source_ip
        
        # Get username safely
        user = username_map.get(src_ip.strip() if src_ip else '', '-')
        
        # Handle NO MATCH
        dst = parsed['dst_ip'] or log.destination_ip
        if dst == '**NO MATCH**': dst = '--'
        if not dst: dst = '-'
        
        # DNS Resolution Logic
        domain = parsed['domain']
        if not domain and resolve_dns and dst and dst != '-':
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(dst)):
                hostname = reverse_dns_cached(dst)
                if hostname:
                    domain = simplify_domain(hostname)
        
        # Normalize type for template (DNS/FW)
        display_type = 'FW'
        if 'DNS' in (parsed['log_type'] or '').upper():
            display_type = 'DNS'
            
        enriched.append({
            'log': log,
            'id': log.id,
            'time': log.log_time,
            'router': log.nas_ip,
            'src_ip': src_ip,
            'dst_ip': dst,
            'domain': domain or '',
            'url': log.url,
            'method': log.method,
            'protocol': parsed['protocol'],
            'port_name': parsed['port_name'],
            'username': user, 
            'log_type': display_type
        })
    return enriched

@login_required
def export_traffic_excel(request):
    """
    Export traffic logs to Excel (.xlsx) with parsed domain/IP info.
    Filters: q, router, users_only, start_date, end_date.
    """
    search_query = request.GET.get('q', '').strip()
    selected_router = request.GET.get('router', '').strip()
    users_only = request.GET.get('users_only', '') == '1'
    web_only = request.GET.get('web_only', '') == '1'
    start_date_str = request.GET.get('start_date', '').strip()
    end_date_str = request.GET.get('end_date', '').strip()
    
    # Access Control
    allowed_routers = get_allowed_routers(request.user)
    
    logs_queryset = TrafficLog.objects.using('default').all().order_by('-log_time')

    # Date Filtering
    try:
        from django.utils.dateparse import parse_datetime
        if start_date_str:
            # Try parsing as datetime, fallback to date
            start_dt = parse_datetime(start_date_str)
            if not start_dt:
                 # If input is just YYYY-MM-DD
                 try:
                     start_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
                     start_dt = timezone.make_aware(start_dt)
                 except: pass # Invalid format
            else:
                 if timezone.is_naive(start_dt):
                      start_dt = timezone.make_aware(start_dt)
            if start_dt:
                logs_queryset = logs_queryset.filter(log_time__gte=start_dt)
            
        if end_date_str:
            end_dt = parse_datetime(end_date_str)
            if not end_dt:
                 try:
                     end_dt = datetime.strptime(end_date_str, '%Y-%m-%d')
                     # End of that day
                     end_dt = end_dt.replace(hour=23, minute=59, second=59)
                     end_dt = timezone.make_aware(end_dt)
                 except: pass
            else:
                 if timezone.is_naive(end_dt):
                      end_dt = timezone.make_aware(end_dt)
            if end_dt:
                logs_queryset = logs_queryset.filter(log_time__lte=end_dt)
            
    except Exception as e:
        print(f"Date parsing error: {e}") # Non-blocking

    if allowed_routers is not None:
        logs_queryset = logs_queryset.filter(nas_ip__in=allowed_routers)
    
    if selected_router:
        # Security check
        if allowed_routers is not None and selected_router not in allowed_routers:
            logs_queryset = logs_queryset.none()
        else:
            logs_queryset = logs_queryset.filter(nas_ip=selected_router)
    
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(nas_ip__icontains=search_query) |
            Q(source_ip__icontains=search_query) |
            Q(destination_ip__icontains=search_query) |
            Q(url__icontains=search_query) |
            Q(method__icontains=search_query)
        )
        
    # User Only Filter (Match Web View Logic)
    if users_only:
        known_ips = (
            Radacct.objects.using('default')
            .exclude(framedipaddress='')
            .values_list('framedipaddress', flat=True)
            .distinct()
        )
        logs_queryset = logs_queryset.filter(source_ip__in=known_ips)
    
    # Limit to 5000 rows for performance
    logs = list(logs_queryset[:5000])
    
    # Pre-fetch Usernames
    username_map = lookup_usernames_for_logs(logs)

    # Resolve/Enrich for export if web_only is active
    # We use a bit of logic from enrich_logs here
    final_logs = []
    for log in logs:
        parsed = parse_log_entry(log.url, log.method)
        domain = parsed['domain']
        dst = parsed['dst_ip'] or log.destination_ip
        
        # DNS Resolution for export if needed (simplified)
        if not domain and dst and dst != '-' and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(dst)):
             # We skip full resolve_cached here for export speed unless it's a small batch
             # But for consistency, let's just use what parse_log_entry found
             pass
        
        if web_only and not domain:
             continue
             
        final_logs.append((log, parsed, domain))

    # Create Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Traffic Logs"
    
    # Styles
    header_font = Font(name='Calibri', bold=True, color='FFFFFF', size=11)
    header_fill = PatternFill(start_color='1E293B', end_color='1E293B', fill_type='solid')
    header_align = Alignment(horizontal='center', vertical='center')
    thin_border = Border(bottom=Side(style='thin', color='E2E8F0'))
    
    cell_font = Font(name='Calibri', size=10)
    domain_font = Font(name='Calibri', size=10, bold=True, color='1D4ED8')
    ip_font = Font(name='Consolas', size=10, color='0F766E')
    user_font = Font(name='Calibri', size=10, bold=True, color='D97706') # Amber color for user
    
    # Headers (Added Username)
    headers = ['Type', 'Time', 'Router (NAS)', 'Client IP', 'Username', 'Domain / Website', 'Dest IP', 'Port', 'Protocol']
    
    for col, header in enumerate(headers, 1):
        c = ws.cell(row=1, column=col, value=header)
        c.font = header_font
        c.fill = header_fill
        c.alignment = header_align

    # Data Rows
    for row_idx, (log, parsed, domain) in enumerate(final_logs, 2):
        client_ip = parsed['client_ip'] or log.source_ip
        
        # 1. Type
        ws.cell(row=row_idx, column=1, value=parsed['log_type']).font = cell_font
        
        # 2. Time
        ws.cell(row=row_idx, column=2, value=log.log_time.strftime('%Y-%m-%d %H:%M:%S') if log.log_time else '').font = cell_font
        
        # 3. Router
        ws.cell(row=row_idx, column=3, value=log.nas_ip or '').font = ip_font
        
        # 4. Client IP
        ws.cell(row=row_idx, column=4, value=client_ip).font = ip_font
        
        # 5. Username (New)
        username = username_map.get(client_ip, '-')
        ws.cell(row=row_idx, column=5, value=username).font = user_font
        
        # 6. Domain / Website
        display_domain = domain
        if not display_domain:
             display_domain = log.url if log.url and log.url != '-' else (log.method or '')
             
        c = ws.cell(row=row_idx, column=6, value=display_domain)
        c.font = cell_font # Use normal font
        
        # 7. Dest IP
        display_dst = parsed['dst_ip'] or ''
        if display_dst == '**NO MATCH**' or not display_dst:
            display_dst = '--'
        ws.cell(row=row_idx, column=7, value=display_dst).font = ip_font
        
        # 8. Port
        ws.cell(row=row_idx, column=8, value=parsed['port_name'] or '').font = cell_font
        
        # 9. Protocol
        ws.cell(row=row_idx, column=9, value=parsed['protocol'] or '').font = cell_font
    
    # Auto-size columns
    col_widths = [10, 20, 16, 16, 20, 40, 16, 10, 10]
    for i, width in enumerate(col_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = width
    
    # Freeze top row
    ws.freeze_panes = 'A2'
    
    # Response
    from datetime import datetime as dt
    filename = f"traffic_logs_{dt.now().strftime('%Y%m%d_%H%M')}.xlsx"
    
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    wb.save(response)
    return response
@login_required
def traffic_log_report(request):
    """
    Traffic Log Report for Computer Crime Act Compliance:
    1. Input: username, date
    2. Logic:
       - Find sessions in Radacct where (User == username) active on the given date.
       - Get the framedipaddress (IP) for those sessions.
       - Query TrafficLog for logs where (source_ip == IP) and log_time falls within Session Start/Stop.
       - Join the data: Log Time, Username (from input), IP (from Log/Session), Website (from Log).
    """
    search_username = request.GET.get('username', '').strip()
    search_date_str = request.GET.get('date', '')
    
    logs_result = []
    
    if search_username and search_date_str:
        try:
            # Parse Date
            naive_date = datetime.strptime(search_date_str, '%Y-%m-%d').date()
            # Assuming timezone aware settings
            tz = timezone.get_current_timezone()
            midday = datetime.combine(naive_date, time(12, 0)) # Just for timezone reference
            if timezone.is_aware(timezone.now()):
                 midday = timezone.make_aware(midday, tz)

            start_of_day = midday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = midday.replace(hour=23, minute=59, second=59, microsecond=999999)

            # Step 1: Find Sessions for this User/IP active on this Date
            # Condition: Session started before end of day AND (ended after start of day OR is still active)
            
            # Check if input is an IP address
            import re
            is_ip_search = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", search_username)
            
            query_kwargs = {
                'acctstarttime__lte': end_of_day
            }
            
            if is_ip_search:
                query_kwargs['framedipaddress'] = search_username
            else:
                query_kwargs['username'] = search_username
                
            sessions = Radacct.objects.using('default').filter(
                **query_kwargs
            ).filter(
                Q(acctstoptime__gte=start_of_day) | Q(acctstoptime__isnull=True)
            )
            
            # Apply router access control
            allowed_routers = get_allowed_routers(request.user)
            if allowed_routers is not None:
                sessions = sessions.filter(nasipaddress__in=allowed_routers)
            
            for session in sessions:
                ip = session.framedipaddress
                start_time = session.acctstarttime
                stop_time = session.acctstoptime if session.acctstoptime else timezone.now()
                
                # Check Timezone awareness to avoid naive/aware comparison error
                if timezone.is_aware(start_time) and timezone.is_naive(start_of_day):
                    start_of_day = timezone.make_aware(start_of_day, start_time.tzinfo)
                    end_of_day = timezone.make_aware(end_of_day, start_time.tzinfo)
                
                # Constrain the search window to the intersection of [Day] and [Session]
                search_start = max(start_time, start_of_day)
                search_end = min(stop_time, end_of_day)
                
                if search_start > search_end:
                    continue
                    
                # Step 2: Query TrafficLog
                # Note: 'source_ip' in TrafficLog must match 'framedipaddress'
                # DEBUG: Use naive comparison if DB is naive
                
                # Check if IP exists
                if not ip:
                    continue
                    
                # If no logs found with strict match, try relaxed window (e.g. +/- 1 min skew)
                # AND check destination_ip because Mikrotik logs might put client IP there
                traffic_logs = TrafficLog.objects.using('default').filter(
                    Q(source_ip=ip) | Q(destination_ip=ip),
                    log_time__gte=search_start - timedelta(minutes=5),
                    log_time__lte=search_end + timedelta(minutes=5)
                )
                
                if allowed_routers is not None:
                    traffic_logs = traffic_logs.filter(nas_ip__in=allowed_routers)

                traffic_logs = traffic_logs.values('log_time', 'source_ip', 'destination_ip', 'url', 'method')

                for log in traffic_logs:
                    # Determine which field holds the meaningful info (URL vs Message)
                    parsed = parse_log_entry(log['url'], log['method'])
                    website_info = parsed['domain']
                    dst_ip = log['destination_ip']

                    # Resolve DNS for Compliance Report
                    if not website_info and dst_ip:
                         if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(dst_ip)):
                              hostname = reverse_dns_cached(dst_ip)
                              if hostname:
                                   website_info = simplify_domain(hostname)
                    
                    if not website_info:
                        website_info = log['url']
                        if website_info == '0.0.0.0' or website_info == '-':
                            website_info = log['method'] or log['url']
                        if log['method'] and len(log['method']) > 20: 
                            website_info = log['method']

                    logs_result.append({
                        'time': log['log_time'],
                        'username': search_username,
                        'ip': ip,
                        'website': website_info,
                        'destination_ip': dst_ip if dst_ip != ip else log['source_ip']
                    })
                    
        except ValueError:
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
        except Exception as e:
            messages.error(request, f"Error searching logs: {str(e)}")
            import traceback
            print(traceback.format_exc()) # Print to console for debugging
    
    # Sort results by time descending
    logs_result.sort(key=lambda x: x['time'], reverse=True)
    
    # Validation Message for User
    if search_username and not logs_result:
        messages.info(request, f"No traffic logs found for user '{search_username}' on {search_date_str}. Verified sessions existence? { 'Yes' if 'sessions' in locals() and sessions.exists() else 'No' }.")
    
    return render(request, 'hotspot/traffic_log_report.html', {
        'logs': logs_result,
        'search_username': search_username,
        'search_date': search_date_str
    })


# Helpers



@login_required
def traffic_log_list(request):
    """
    General viewer for Traffic Logs.
    Uses cursor-based pagination for performance on large tables.
    """
    search_query = request.GET.get('q', '').strip()
    resolve_dns = request.GET.get('resolve', '1') == '1'
    selected_router = request.GET.get('router', '').strip()
    users_only = request.GET.get('users_only', '') == '1'
    web_only = request.GET.get('web_only', '') == '1'
    start_date_str = request.GET.get('start_date', '').strip()
    end_date_str = request.GET.get('end_date', '').strip()
    before_id = request.GET.get('before', '')  # cursor: show records with id < this
    per_page = 50
    
    # Get allowed routers for this user
    allowed_routers = get_allowed_routers(request.user)
    
    # Get distinct routers for dropdown (cached by DB)
    routers_qs = (
        TrafficLog.objects.using('default')
        .exclude(nas_ip__isnull=True)
        .exclude(nas_ip='')
        .values_list('nas_ip', flat=True)
        .distinct()
        .order_by('nas_ip')
    )
    
    if allowed_routers is not None:
        routers_qs = routers_qs.filter(nas_ip__in=allowed_routers)
        
    routers = routers_qs
    
    # Build queryset
    logs_queryset = TrafficLog.objects.using('default').all().order_by('-id')
    
    # Router Access Control
    if allowed_routers is not None:
        logs_queryset = logs_queryset.filter(nas_ip__in=allowed_routers)
    
    # Router filter (User selection)
    if selected_router:
        # Security check: if user restricted, ensure selected router is allowed
        if allowed_routers is not None and selected_router not in allowed_routers:
             logs_queryset = logs_queryset.none()
        else:
             logs_queryset = logs_queryset.filter(nas_ip=selected_router)
    
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(nas_ip__icontains=search_query) |
            Q(source_ip__icontains=search_query) |
            Q(destination_ip__icontains=search_query) |
            Q(url__icontains=search_query) |
            Q(method__icontains=search_query)
        )

    # Date Filtering
    try:
        from django.utils.dateparse import parse_datetime
        if start_date_str:
            start_dt = parse_datetime(start_date_str)
            if not start_dt:
                 try:
                     start_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
                     start_dt = timezone.make_aware(start_dt)
                 except: pass
            else:
                 if timezone.is_naive(start_dt):
                      start_dt = timezone.make_aware(start_dt)
            if start_dt:
                logs_queryset = logs_queryset.filter(log_time__gte=start_dt)
            
        if end_date_str:
            end_dt = parse_datetime(end_date_str)
            if not end_dt:
                 try:
                     end_dt = datetime.strptime(end_date_str, '%Y-%m-%d')
                     end_dt = end_dt.replace(hour=23, minute=59, second=59)
                     end_dt = timezone.make_aware(end_dt)
                 except: pass
            else:
                 if timezone.is_naive(end_dt):
                      end_dt = timezone.make_aware(end_dt)
            if end_dt:
                logs_queryset = logs_queryset.filter(log_time__lte=end_dt)
    except Exception as e:
        print(f"Date parsing error: {e}") 
    
    # Pre-filter: only IPs that exist in radacct (known users)
    if users_only:
        known_ips = (
            Radacct.objects.using('default')
            .exclude(framedipaddress='')
            .values_list('framedipaddress', flat=True)
            .distinct()
        )
        logs_queryset = logs_queryset.filter(source_ip__in=known_ips)
    
    # Cursor-based pagination: fetch before this ID
    if before_id:
        try:
            logs_queryset = logs_queryset.filter(id__lt=int(before_id))
        except ValueError:
            pass
    
    # Fetch per_page + 1 to check if there are more
    logs_list = list(logs_queryset[:per_page + 1])
    has_next = len(logs_list) > per_page
    logs_list = logs_list[:per_page]
    
    # Get next cursor (last item's ID)
    next_before_id = logs_list[-1].id if logs_list and has_next else None
    
    # Enrich with parsed data (domain, dst IP, port, protocol)
    enriched_logs = enrich_logs(logs_list, resolve_dns=resolve_dns)
    
    # Filter for Web/URL Only if requested
    if web_only:
        enriched_logs = [item for item in enriched_logs if item['domain'] and item['domain'] != '-']

    return render(request, 'hotspot/traffic_log_list.html', {
        'logs_list': logs_list,
        'enriched_logs': enriched_logs,
        'search_query': search_query,
        'resolve_dns': resolve_dns,
        'routers': routers,
        'selected_router': selected_router,
        'users_only': users_only,
        'web_only': web_only,
        'has_next': has_next,
        'next_before_id': next_before_id,
        'before_id': before_id,
        'start_date': start_date_str,
        'end_date': end_date_str,
    })



    return response
