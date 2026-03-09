import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from hotspot.traffic_models import TrafficLog
last = TrafficLog.objects.filter(url__contains='#').order_by('-log_time').first()
print(f'Last log with #: {last.log_time if last else "None"}')
if last:
    print(f'Content: {last.url}')

last_http = TrafficLog.objects.filter(url__contains='://').order_by('-log_time').first()
print(f'Last HTTP log: {last_http.log_time if last_http else "None"}')
