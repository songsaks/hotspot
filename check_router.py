import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.traffic_models import TrafficLog
from django.db.models import Count

routers = list(TrafficLog.objects.values_list('nas_ip', flat=True).distinct())
print(f"Distinct Routers: {routers}")
