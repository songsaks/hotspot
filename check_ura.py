import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import UserRouterAccess

routers = UserRouterAccess.objects.values_list('router_ip', flat=True).distinct()
print(f"Routers in UserRouterAccess: {list(routers)}")
