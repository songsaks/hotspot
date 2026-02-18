import os
import django
from datetime import datetime
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct
from hotspot.traffic_models import TrafficLog

def inspect_data():
    print("--- RAW DATA INSPECTION: Check specific subnet ---")
    logs = TrafficLog.objects.using('default').filter(source_ip__startswith='10.20.').order_by('-log_time')[:5]
    if not logs:
        print(">> No logs found for subnet 10.20.x.x at all.")
    else:
        print(f">> Found {logs.count()} logs for subnet 10.20.x.x:")
        for l in logs:
            print(f"Time: {l.log_time} | IP: {l.source_ip} | URL: {l.url}")
            
    print("\n--- Checking Radacct for User 5390 ---")
    username = '5390'
    today = timezone.now().date()
    sessions = Radacct.objects.using('default').filter(username=username).order_by('-acctstarttime')[:5]
    if not sessions:
        print("No sessions found for user 5390.")
    else:
        for s in sessions:
            print(f"Session Start: {s.acctstarttime} | IP: {s.framedipaddress}")

if __name__ == "__main__":
    inspect_data()
