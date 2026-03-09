import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct

count = Radacct.objects.filter(nasipaddress='10.1.1.12').using('default').count()
print(f"Radacct sessions for 10.1.1.12: {count}")
