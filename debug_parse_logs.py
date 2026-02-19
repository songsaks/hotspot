"""
Debug: Check BOTH url and method fields for patterns
"""
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

import re
from hotspot.traffic_models import TrafficLog

logs = TrafficLog.objects.using('default').order_by('-log_time')[:30]

print(f"Total logs: {TrafficLog.objects.using('default').count()}")
print()

for i, log in enumerate(logs):
    url = log.url or ''
    method = log.method or ''
    combined = url + ' ' + method  # Check both fields
    
    # DNS query pattern in either field
    dns_match = re.search(r'from\s+([\d.]+):\s+#\d+\s+(\S+)\s+(A|AAAA|CNAME|MX|TXT|PTR|SRV|NS)', combined)
    
    # IP->IP pattern in either field
    fw_match = re.search(r'([\d.]+):(\d+)->([\d.]+):(\d+)', combined)
    
    log_type = "???"
    info = ""
    
    if dns_match:
        client_ip = dns_match.group(1)
        domain = dns_match.group(2).rstrip('.')
        record_type = dns_match.group(3)
        log_type = "DNS"
        info = f"Client: {client_ip} -> Domain: {domain} ({record_type})"
    elif fw_match:
        src_ip = fw_match.group(1)
        dst_ip = fw_match.group(3)
        dst_port = fw_match.group(4)
        log_type = "FW"
        info = f"{src_ip} -> {dst_ip}:{dst_port}"
    
    print(f"[{log_type}] {info}")
    if log_type == "???":
        print(f"  URL field:    '{url[:120]}'")
        print(f"  Method field: '{method[:120]}'")
    print()
