import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()

from hotspot.traffic_models import TrafficLog

total = TrafficLog.objects.count()
print(f"Total TrafficLog rows: {total}")

# Sample 20 latest rows
print("\n--- Sample 20 latest rows ---")
logs = TrafficLog.objects.order_by('-log_time')[:20].values(
    'log_time', 'nas_ip', 'source_ip', 'url', 'method', 'bytes_sent', 'bytes_received'
)
for l in logs:
    url_preview = str(l['url'] or '')[:80]
    method_preview = str(l['method'] or '')[:80]
    print(f"  [{l['log_time']}] src={str(l['source_ip']):15} | url='{url_preview}' | method='{method_preview}'")

# Check if ANY rows have domain-like URLs
print("\n--- URLs that contain '://' (HTTP/HTTPS) ---")
http_count = TrafficLog.objects.filter(url__contains='://').count()
print(f"  Rows with '://' in url: {http_count}")

print("\n--- URLs that contain 'CONNECT' (HTTPS proxy) ---")
connect_count = TrafficLog.objects.filter(method__icontains='CONNECT').count()
print(f"  Rows with CONNECT in method: {connect_count}")

print("\n--- URLs that contain 'got query' (DNS log) ---")
dns_count = TrafficLog.objects.filter(url__icontains='got query').count()
print(f"  Rows with DNS query in url: {dns_count}")

print("\n--- Distinct unique URL patterns (first 10) ---")
sample_urls = TrafficLog.objects.exclude(url__isnull=True).exclude(url='').order_by('-log_time').values_list('url', flat=True)[:10]
for u in sample_urls:
    print(f"  url: {str(u)[:120]}")

print("\n--- Distinct unique METHOD patterns (first 10) ---")
sample_methods = TrafficLog.objects.exclude(method__isnull=True).exclude(method='').order_by('-log_time').values_list('method', flat=True)[:10]
for m in sample_methods:
    print(f"  method: {str(m)[:120]}")

print("\n--- nas_ip distribution ---")
from django.db.models import Count
nas_dist = TrafficLog.objects.values('nas_ip').annotate(cnt=Count('id')).order_by('-cnt')[:10]
for n in nas_dist:
    print(f"  nas_ip={n['nas_ip']}  count={n['cnt']}")
