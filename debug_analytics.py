import os
import django
from django.utils import timezone
from django.db.models import Sum, Count, F
from django.db.models.functions import Coalesce, TruncDate
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct

def check_analytics():
    print(f"Current Time (Django): {timezone.now()}")
    today = timezone.now().date()
    yesterday_7d = today - timedelta(days=6)
    print(f"Today (Local): {today}")
    
    # Check 1: Real-time Active
    active = Radacct.objects.using('default').filter(acctstoptime__isnull=True).count()
    print(f"Active Users: {active}")
    
    # Check 2: Today's Stats
    # Query blindly first without date filter
    last_session = Radacct.objects.using('default').last()
    if last_session:
        print(f"Last Session in DB: {last_session.acctstarttime} (Raw)")
    else:
        print("Table Radacct is empty!")
        return

    today_count = Radacct.objects.using('default').filter(acctstarttime__date=today).count()
    print(f"Sessions starting 'Today' ({today}): {today_count}")
    
    # Verify strict date range instead of __date transform
    start_of_day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    print(f"Start of Day (Aware): {start_of_day}")
    
    today_count_strict = Radacct.objects.using('default').filter(acctstarttime__gte=start_of_day).count()
    print(f"Sessions >= Start of Day: {today_count_strict}")

    # Check 3: 7 Days
    history_count = Radacct.objects.using('default').filter(acctstarttime__date__gte=yesterday_7d).count()
    print(f"Sessions Last 7 Days: {history_count}")
    
    if history_count == 0:
        print("!! No history found. Showing last 5 sessions to check dates:")
        obs = Radacct.objects.using('default').order_by('-acctstarttime')[:5]
        for o in obs:
            print(f" - {o.acctstarttime} (Stop: {o.acctstoptime})")

if __name__ == "__main__":
    check_analytics()
