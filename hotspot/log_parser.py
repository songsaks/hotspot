"""
Utility to parse Mikrotik traffic log entries and extract
meaningful information (Domain, Destination IP, Protocol, Port).
"""
import re
import socket
from functools import lru_cache

# --- Regex Patterns ---

# DNS Query: "from 192.168.1.97: #38999557 v16-cla.tiktokcdn.com. A"
DNS_PATTERN = re.compile(
    r'from\s+([\d.]+):\s+#\d+\s+(\S+?)\.\s+(A|AAAA|CNAME|MX|TXT|PTR|SRV|NS|SOA|ANY)'
)

# Firewall Forward: "192.168.1.97:50701->142.251.153.119:443"
FW_PATTERN = re.compile(
    r'([\d.]+):(\d+)->([\d.]+):(\d+)'
)

# Protocol: "proto TCP (SYN)" or "proto UDP"
PROTO_PATTERN = re.compile(r'proto\s+(\w+)')

# Well-known ports
PORT_NAMES = {
    '80': 'HTTP',
    '443': 'HTTPS',
    '53': 'DNS',
    '22': 'SSH',
    '21': 'FTP',
    '25': 'SMTP',
    '110': 'POP3',
    '143': 'IMAP',
    '993': 'IMAPS',
    '995': 'POP3S',
    '3389': 'RDP',
    '8080': 'HTTP-Alt',
    '8443': 'HTTPS-Alt',
}

# Simple DNS cache (in-memory, per process)
_dns_cache = {}


def reverse_dns_cached(ip):
    """Reverse DNS lookup with in-memory cache."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Simplify: extract main domain
        _dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        _dns_cache[ip] = None
        return None


def simplify_domain(hostname):
    """
    Try to extract a recognizable domain from hostname.
    e.g. 'lhr25s34-in-f14.1e100.net' -> '1e100.net (Google)'
    e.g. 'edge-star-mini-shv-01-bkk1.facebook.com' -> 'facebook.com'
    """
    if not hostname:
        return None
    
    parts = hostname.split('.')
    if len(parts) >= 2:
        # Return last 2 parts as domain
        return '.'.join(parts[-2:])
    return hostname


def parse_log_entry(url_field, method_field):
    """
    Parse a single traffic log entry.
    
    Returns dict with:
    - log_type: 'DNS' | 'FW' | 'UNKNOWN'
    - domain: resolved domain name (if available)
    - dst_ip: destination IP
    - dst_port: destination port  
    - port_name: human-readable port name
    - protocol: TCP/UDP etc
    - client_ip: source/client IP from the log
    """
    combined = (url_field or '') + ' ' + (method_field or '')
    
    result = {
        'log_type': 'UNKNOWN',
        'domain': None,
        'dst_ip': None,
        'dst_port': None,
        'port_name': None,
        'protocol': None,
        'client_ip': None,
    }
    
    # Check DNS query first (has domain directly)
    dns_match = DNS_PATTERN.search(combined)
    if dns_match:
        result['log_type'] = 'DNS'
        result['client_ip'] = dns_match.group(1)
        result['domain'] = dns_match.group(2).rstrip('.')
        return result
    
    # Check Firewall Forward log
    fw_match = FW_PATTERN.search(combined)
    if fw_match:
        result['log_type'] = 'FW'
        result['client_ip'] = fw_match.group(1)
        result['dst_ip'] = fw_match.group(3)
        result['dst_port'] = fw_match.group(4)
        result['port_name'] = PORT_NAMES.get(fw_match.group(4), f'Port {fw_match.group(4)}')
        
        # Extract protocol
        proto_match = PROTO_PATTERN.search(combined)
        if proto_match:
            result['protocol'] = proto_match.group(1)
        
        return result
    
    return result


def enrich_logs(logs_page, resolve_dns=False):
    """
    Take a page of TrafficLog objects and enrich them with parsed info.
    
    Returns list of dicts with original log data + parsed fields.
    """
    enriched = []
    
    for log in logs_page:
        parsed = parse_log_entry(log.url, log.method)
        
        # Try reverse DNS for FW logs if enabled
        domain = parsed['domain']
        if resolve_dns and parsed['log_type'] == 'FW' and parsed['dst_ip']:
            hostname = reverse_dns_cached(parsed['dst_ip'])
            if hostname:
                domain = simplify_domain(hostname)
        
        enriched.append({
            'log': log,
            'log_type': parsed['log_type'],
            'domain': domain,
            'dst_ip': parsed['dst_ip'],
            'dst_port': parsed['dst_port'],
            'port_name': parsed['port_name'],
            'protocol': parsed['protocol'],
            'client_ip': parsed['client_ip'],
        })
    
    return enriched
