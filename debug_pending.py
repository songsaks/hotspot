import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import PendingUser
from django.db.models import Count

print(f"Total pending: {PendingUser.objects.count()}")
print()

# Check duplicates
dupes = PendingUser.objects.values('username').annotate(cnt=Count('id')).filter(cnt__gt=1)
print("Duplicate usernames:")
for d in dupes:
    print(f"  {d['username']}: {d['cnt']} entries")

if not dupes:
    print("  (none found - checking case-insensitive...)")
    # Case-insensitive duplicates
    from django.db.models.functions import Lower
    dupes_ci = PendingUser.objects.annotate(lower_name=Lower('username')).values('lower_name').annotate(cnt=Count('id')).filter(cnt__gt=1)
    for d in dupes_ci:
        print(f"  {d['lower_name']}: {d['cnt']} entries (case-insensitive)")

print()
print("All pending users:")
for u in PendingUser.objects.all().order_by('-created_at'):
    print(f"  ID={u.pk}, username='{u.username}', name='{u.full_name}', phone='{u.phone}', created={u.created_at}")
