import os, django, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct
from hotspot.traffic_models import TrafficLog
from django.utils import timezone

logs = TrafficLog.objects.exclude(source_ip='').order_by('-log_time')[:10]
print("Recent traffic logs:")
for l in logs:
    print(f"Log: {l.log_time} ({type(l.log_time)}), SrcIP: {l.source_ip}, NAS: {l.nas_ip}")

sessions = Radacct.objects.using('default').order_by('-acctstarttime')[:10]
print("\nRecent Radacct sessions:")
for s in sessions:
    print(f"Sess: Start {s.acctstarttime} ({type(s.acctstarttime)}), Stop {s.acctstoptime}, IP: {s.framedipaddress}, User: {s.username}")
