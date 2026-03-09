import os, django, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.traffic_models import TrafficLog
from hotspot.log_parser import reverse_dns_cached, simplify_domain
from django.db.models import Count, Sum
from django.db.models.functions import Coalesce
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# --- Domain Map (same as in views_traffic) ---
DOMAIN_MAP = {
    '1e100.net': 'google.com', 'googleusercontent.com': 'google.com',
    'googleapis.com': 'google.com', 'gstatic.com': 'google.com',
    'googlevideo.com': 'youtube.com', 'ytimg.com': 'youtube.com',
    'fbcdn.net': 'facebook.com', 'facebook.net': 'facebook.com',
    'tiktokcdn.com': 'tiktok.com', 'byteoversea.com': 'tiktok.com',
    'line-scdn.net': 'line.me', 'line-apps.com': 'line.me',
    'amazonaws.com': 'amazonaws.com', 'cloudfront.net': 'cloudfront.net',
}

def map_domain(raw):
    if not raw: return raw
    d = raw.lower().strip()
    if d.startswith('www.'): d = d[4:]
    if d in DOMAIN_MAP: return DOMAIN_MAP[d]
    for tech, human in DOMAIN_MAP.items():
        if d.endswith('.' + tech) or d == tech: return human
    return d

def is_public_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4: return False
    try: a, b = int(parts[0]), int(parts[1])
    except: return False
    if a in (10, 127, 0): return False
    if a == 172 and 16 <= b <= 31: return False
    if a == 192 and b == 168: return False
    return True

now = datetime.now()
start_dt = now - timedelta(days=1)

print(f"Speed test: Top Websites (last 24h)")
t0 = time.time()

qs = TrafficLog.objects.all().filter(log_time__gte=start_dt)

# Phase 1: DB aggregation
t1 = time.time()
ip_agg = list(
    qs.values('destination_ip')
    .annotate(
        visit_count=Count('id'),
        total_bytes=Coalesce(Sum('bytes_sent'), 0) + Coalesce(Sum('bytes_received'), 0),
    )
    .order_by('-visit_count')[:200]
)
t2 = time.time()
print(f"Phase 1 (DB GROUP BY): {t2-t1:.1f}s — {len(ip_agg)} IPs")

# Phase 2: Filter + Parallel DNS resolve
public_ips = [e for e in ip_agg if e['destination_ip'] and is_public_ip(e['destination_ip'])][:100]
print(f"Public IPs to resolve: {len(public_ips)} (filtered from {len(ip_agg)})")

def resolve_ip(ip):
    hostname = reverse_dns_cached(ip)
    if hostname:
        domain = simplify_domain(hostname)
        return ip, map_domain(domain)
    return ip, None

t3 = time.time()
ip_to_domain = {}
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(resolve_ip, e['destination_ip']): e for e in public_ips}
    for future in as_completed(futures):
        try:
            ip, domain = future.result()
            ip_to_domain[ip] = domain
        except: pass

t4 = time.time()
print(f"Phase 2 (Parallel DNS {len(public_ips)} IPs): {t4-t3:.1f}s")

# Phase 3: Merge
domain_stats = {}
for entry in ip_agg:
    ip = entry['destination_ip']
    domain = ip_to_domain.get(ip)
    if not domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        continue
    if domain not in domain_stats:
        domain_stats[domain] = {'count': 0, 'bytes': 0}
    domain_stats[domain]['count'] += entry['visit_count']
    domain_stats[domain]['bytes'] += entry['total_bytes'] or 0

sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:20]
t5 = time.time()

print(f"\nTotal time: {t5-t0:.1f}s")
print(f"\nTop 20 Websites:")
for rank, (domain, stats) in enumerate(sorted_domains, 1):
    mb = round(stats['bytes'] / (1024*1024), 1)
    print(f"  {rank}. {domain}: {stats['count']:,} visits ({mb} MB)")
