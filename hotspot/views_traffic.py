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
