import os
import django
import sys

# Change to module directory or set environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct
from hotspot.traffic_models import TrafficLog
from hotspot.views_traffic import lookup_active_sessions_for_logs, enrich_logs, parse_log_entry

logs = list(TrafficLog.objects.order_by('-log_time')[:10])
print(f"Got {len(logs)} logs")
if logs:
    min_time = min(l.log_time for l in logs)
    max_time = max(l.log_time for l in logs)
    print(f"Min time: {min_time} ({type(min_time)}), Max time: {max_time} ({type(max_time)})")
    
    ips = set(l.source_ip for l in logs)
    print(f"Source IPs: {ips}")
    
    # Check Radacct
    sessions = Radacct.objects.using('default').filter(framedipaddress__in=ips).order_by('-acctstarttime')
    print(f"Total sessions for these IPs: {sessions.count()}")
    for s in sessions[:5]:
        print(f"  Session: User={s.username}, IP={s.framedipaddress}, Start={s.acctstarttime} ({type(s.acctstarttime)}), Stop={s.acctstoptime} ({type(s.acctstoptime)})")
        
    active = lookup_active_sessions_for_logs(logs)
    print(f"Overlapping sessions found (dict): {len(active)}")
    
    for a in active[:5]:
         print(f"  Active mapping: User={a['username']}, IP={a['framedipaddress']}, Start={a['acctstarttime']}, Stop={a['acctstoptime']}")
    
    # Enrich and test
    enriched = enrich_logs(logs)
    for e in enriched:
        print(f"Log time: {e['time']}, IP: {e['src_ip']}, User: {e['username']}")
