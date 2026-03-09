import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.traffic_models import TrafficLog
from django.db.models import Count

print("--- Router Stats ---")
routers = TrafficLog.objects.using('default').values('nas_ip').annotate(count=Count('id')).order_by('nas_ip')
for r in routers:
    print(f"Router: '{r['nas_ip']}', Count: {r['count']}")
