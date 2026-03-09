import os
import sys
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
sys.path.insert(0, os.getcwd())
django.setup()

from hotspot.traffic_models import TrafficLog
from hotspot.views_traffic import parse_log_entry
from datetime import datetime, timedelta
import re

now = datetime.now()
yesterday = now - timedelta(days=14)
print(f"Checking logs since: {yesterday}")

# Check for port 53 (DNS)
p53_count = TrafficLog.objects.filter(log_time__gte=yesterday, url__icontains=':53').count()
print(f"Logs containing ':53' (potentially DNS): {p53_count}")
if p53_count > 0:
    samples = TrafficLog.objects.filter(log_time__gte=yesterday, url__icontains=':53').order_by('-log_time')[:5]
    for s in samples:
        print(f"  - [{s.log_time}] {s.url[:150]}")

dns_patterns = ['got query from', 'got answer from', 'from']
for pattern in dns_patterns:
    count = TrafficLog.objects.filter(log_time__gte=yesterday, url__icontains=pattern).count()
    print(f"Pattern '{pattern}': {count}")
    if count > 0:
        sample = TrafficLog.objects.filter(log_time__gte=yesterday, url__icontains=pattern).order_by('-log_time')[:5]
        for s in sample:
            parsed = parse_log_entry(s.url, s.method)
            print(f"  - [{s.log_time}] URL: {s.url[:150]}")
            print(f"    Parsed Domain: {parsed.get('domain')}")

# Top Websites aggregation simulation
print("\n--- Top Websites Aggregation Simulation (Last 14 Days) ---")
# Use a larger sample or a filter
qs = TrafficLog.objects.filter(log_time__gte=yesterday)
print(f"Total candidate logs: {qs.count()}")

# Try to find at least ONE record with a domain to see what it looks like
sample_with_domain = None
for l in qs.iterator():
    parsed = parse_log_entry(l.url, l.method)
    if parsed.get('domain') and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.get('domain')):
        print(f"Found a record with domain: [{l.log_time}] URL: {l.url[:100]} | Domain: {parsed.get('domain')}")
        sample_with_domain = l
        break

if not sample_with_domain:
    print("Could not find a single record with a domain in the last 14 days among all logs.")

# Find when was the LAST time we had a domain log
last_domain_log = None
# This might be slow if the table is huge, but let's try to find any recently.
# We'll check the last 10000 logs specifically.
recent_subset = TrafficLog.objects.all().order_by('-log_time')[:10000]
count = 0
for l in recent_subset:
    p = parse_log_entry(l.url, l.method)
    if p.get('domain') and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', p.get('domain')):
        count += 1
        if count == 1:
            print(f"Most recent domain log found at: {l.log_time} | Domain: {p.get('domain')}")

print(f"Found {count} domain logs in the most recent 10,000 logs.")
