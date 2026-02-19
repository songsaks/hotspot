from django.shortcuts import render
from django.db.models import Q
from django.db.models import Q
from datetime import datetime, time, timedelta
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Radacct
from .traffic_models import TrafficLog

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
                ).values('log_time', 'source_ip', 'destination_ip', 'url', 'method')

                for log in traffic_logs:
                    # Determine which field holds the meaningful info (URL vs Message)
                    website_info = log['url']
                    if website_info == '0.0.0.0' or website_info == '-':
                        # Log message is likely in 'method' or combined
                        website_info = log['method'] or log['url']

                    # Check if 'method' is actually holding the message
                    if log['method'] and len(log['method']) > 20: 
                         website_info = log['method']

                    logs_result.append({
                        'time': log['log_time'],
                        'username': search_username,
                        'ip': ip,
                        'website': website_info,
                        'destination_ip': log['destination_ip'] if log['destination_ip'] != ip else log['source_ip']
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

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .log_parser import enrich_logs

@login_required
def traffic_log_list(request):
    """
    General viewer for Traffic Logs.
    Parses Mikrotik firewall/DNS logs to extract domains and IPs.
    """
    search_query = request.GET.get('q', '').strip()
    resolve_dns = request.GET.get('resolve', '') == '1'
    selected_router = request.GET.get('router', '').strip()
    
    # Get distinct routers for dropdown
    routers = (
        TrafficLog.objects.using('default')
        .exclude(nas_ip__isnull=True)
        .exclude(nas_ip='')
        .values_list('nas_ip', flat=True)
        .distinct()
        .order_by('nas_ip')
    )
    
    # Use 'default' database
    logs_queryset = TrafficLog.objects.using('default').all().order_by('-log_time')
    
    # Router filter
    if selected_router:
        logs_queryset = logs_queryset.filter(nas_ip=selected_router)
    
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(source_ip__icontains=search_query) |
            Q(destination_ip__icontains=search_query) |
            Q(url__icontains=search_query) |
            Q(method__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(logs_queryset, 50) # 50 logs per page
    page = request.GET.get('page')
    
    try:
        logs_page = paginator.page(page)
    except PageNotAnInteger:
        logs_page = paginator.page(1)
    except EmptyPage:
        logs_page = paginator.page(paginator.num_pages)
    
    # Enrich with parsed data (domain, dst IP, port, protocol)
    enriched_logs = enrich_logs(logs_page, resolve_dns=resolve_dns)
        
    return render(request, 'hotspot/traffic_log_list.html', {
        'logs': logs_page,
        'enriched_logs': enriched_logs,
        'search_query': search_query,
        'resolve_dns': resolve_dns,
        'routers': routers,
        'selected_router': selected_router,
    })


from django.http import HttpResponse
from .log_parser import parse_log_entry
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

@login_required
def export_traffic_excel(request):
    """
    Export traffic logs to Excel (.xlsx) with parsed domain/IP info.
    Respects current search filter. Max 5000 rows.
    """
    search_query = request.GET.get('q', '').strip()
    selected_router = request.GET.get('router', '').strip()
    
    logs_queryset = TrafficLog.objects.using('default').all().order_by('-log_time')
    
    if selected_router:
        logs_queryset = logs_queryset.filter(nas_ip=selected_router)
    
    if search_query:
        logs_queryset = logs_queryset.filter(
            Q(source_ip__icontains=search_query) |
            Q(destination_ip__icontains=search_query) |
            Q(url__icontains=search_query) |
            Q(method__icontains=search_query)
        )
    
    # Limit to 5000 rows
    logs = logs_queryset[:5000]
    
    # Create Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Traffic Logs"
    
    # Styles
    header_font = Font(name='Calibri', bold=True, color='FFFFFF', size=11)
    header_fill = PatternFill(start_color='1E293B', end_color='1E293B', fill_type='solid')
    header_align = Alignment(horizontal='center', vertical='center')
    thin_border = Border(
        bottom=Side(style='thin', color='E2E8F0')
    )
    cell_font = Font(name='Calibri', size=10)
    domain_font = Font(name='Calibri', size=10, bold=True, color='1D4ED8')
    ip_font = Font(name='Consolas', size=10, color='0F766E')
    
    # Headers
    headers = ['Type', 'Time', 'Router (NAS)', 'Client IP', 'Domain / Website', 'Dest IP', 'Port', 'Protocol']
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align
    
    # Data Rows
    for row_idx, log in enumerate(logs, 2):
        parsed = parse_log_entry(log.url, log.method)
        
        # Type
        ws.cell(row=row_idx, column=1, value=parsed['log_type']).font = cell_font
        
        # Time (raw from DB)
        ws.cell(row=row_idx, column=2, value=log.log_time.strftime('%Y-%m-%d %H:%M:%S') if log.log_time else '').font = cell_font
        
        # Router (NAS)
        ws.cell(row=row_idx, column=3, value=log.nas_ip or '').font = ip_font
        
        # Client IP
        client_ip = parsed['client_ip'] or log.source_ip
        ws.cell(row=row_idx, column=4, value=client_ip).font = ip_font
        
        # Domain
        domain = parsed['domain'] or ''
        c = ws.cell(row=row_idx, column=5, value=domain)
        c.font = domain_font if domain else cell_font
        
        # Dest IP
        ws.cell(row=row_idx, column=6, value=parsed['dst_ip'] or '').font = ip_font
        
        # Port
        ws.cell(row=row_idx, column=7, value=parsed['port_name'] or '').font = cell_font
        
        # Protocol
        ws.cell(row=row_idx, column=8, value=parsed['protocol'] or '').font = cell_font
        
        # Row border
        for col in range(1, 9):
            ws.cell(row=row_idx, column=col).border = thin_border
    
    # Auto-size columns
    col_widths = [8, 20, 15, 16, 35, 16, 10, 10]
    for i, width in enumerate(col_widths, 1):
        ws.column_dimensions[chr(64 + i)].width = width
    
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
