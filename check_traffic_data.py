
import os
import django
from django.conf import settings

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct
from hotspot.traffic_models import TrafficLog

print("=== Traffic Logs (Last 5) ===")
logs = TrafficLog.objects.using('default').all().order_by('-id')[:5]
for log in logs:
    print(f"ID: {log.id} | Src: {log.source_ip} | Dst: {log.destination_ip} | URL: {log.url} | Method: {log.method}")

print("\n=== Radacct Sessions (Last 5) ===")
sessions = Radacct.objects.using('default').all().order_by('-radacctid')[:5]
for sess in sessions:
    print(f"User: {sess.username} | IP: {sess.framedipaddress} | Start: {sess.acctstarttime} | Stop: {sess.acctstoptime}")
