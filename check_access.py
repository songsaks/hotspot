import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import UserRouterAccess
from django.contrib.auth.models import User

print("--- User Router Access ---")
for access in UserRouterAccess.objects.all().select_related('user'):
    print(f"User: {access.user.username}, Router: {access.router_ip}, Memo: {access.memo}")
