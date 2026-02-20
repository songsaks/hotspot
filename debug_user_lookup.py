import os, django
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
django.setup()

from hotspot.traffic_models import TrafficLog
from hotspot.views_traffic import lookup_usernames_for_logs

# Get logs for IP 10.20.0.11 (known user IP)
logs = list(TrafficLog.objects.using('default').filter(source_ip='10.20.0.11').order_by('-id')[:5])
print('=== Test with IP 10.20.0.11 ===')
result = lookup_usernames_for_logs(logs)
for log in logs:
    user = result.get(log.id, '--')
    print('id=%d src=%s -> user=%s' % (log.id, log.source_ip, user))

# Also test with recent logs (mixed IPs)
print('\n=== Test with latest 20 logs ===')
logs2 = list(TrafficLog.objects.using('default').order_by('-id')[:20])
result2 = lookup_usernames_for_logs(logs2)
matched = 0
for log in logs2:
    user = result2.get(log.id, '')
    if user:
        matched += 1
        print('id=%d src=%-18s -> user=%s' % (log.id, log.source_ip, user))
print('Matched: %d / %d' % (matched, len(logs2)))
