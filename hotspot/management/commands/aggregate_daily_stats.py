import re
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.db.models import Count, Sum
from hotspot.traffic_models import TrafficLog, DailyWebsiteStats
from hotspot.log_parser import parse_log_entry, reverse_dns_cached, simplify_domain

class Command(BaseCommand):
    help = 'Aggregate TrafficLog into DailyWebsiteStats'

    def add_arguments(self, parser):
        parser.add_argument('--date', type=str, help='Date to aggregate (YYYY-MM-DD)')

    def handle(self, *args, **options):
        # 1. Determine Date (default yesterday)
        if options['date']:
            target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
        else:
            target_date = (datetime.now() - timedelta(days=1)).date()

        self.stdout.write(f"Aggregating stats for: {target_date}")

        # 2. Domain Mapping (Same as in views_traffic for consistency)
        DOMAIN_MAP = {
            '1e100.net': 'google.com', 'googlevideo.com': 'youtube.com',
            'fbcdn.net': 'facebook.com', 'tiktokcdn.com': 'tiktok.com',
            'line-scdn.net': 'line.me', 'msdxcdn.microsoft.com': 'microsoft.com',
        }
        def map_domain(d):
            if not d: return d
            d = d.lower().strip()
            if d.startswith('www.'): d = d[4:]
            if d in DOMAIN_MAP: return DOMAIN_MAP[d]
            for tech, human in DOMAIN_MAP.items():
                if d.endswith('.' + tech): return human
            return d

        # 3. Query Log for that day
        qs = TrafficLog.objects.filter(
            log_time__year=target_date.year,
            log_time__month=target_date.month,
            log_time__day=target_date.day
        )

        total_logs = qs.count()
        if total_logs == 0:
            self.stderr.write(f"No logs found for {target_date}")
            return

        # 4. Group by NAS + Source + Destination IP in DB (To count unique users per site)
        ip_agg = qs.values('nas_ip', 'source_ip', 'destination_ip').annotate(
            visits=Count('id'),
            bytes=Sum('bytes_sent') + Sum('bytes_received')
        ).order_by('-visits')[:500]

        # 5. Resolve and Aggregate in Memory
        final_stats = {} # { (nas_ip, domain): {visits, bytes, users_set} }

        for item in ip_agg:
            nas_ip = item['nas_ip']
            ip = item['destination_ip']
            source_ip = item['source_ip']
            
            # Use cached reverse DNS
            hostname = reverse_dns_cached(ip)
            domain = simplify_domain(hostname) if hostname else None
            
            if not domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                continue
            
            mapped = map_domain(domain)
            key = (nas_ip, mapped)
            
            if key not in final_stats:
                final_stats[key] = {'visits': 0, 'bytes': 0, 'users': set()}
            
            final_stats[key]['visits'] += item['visits']
            final_stats[key]['bytes'] += (item['bytes'] or 0)
            final_stats[key]['users'].add(source_ip)

        # 6. Save to DailyWebsiteStats (Top 50 per NAS)
        save_count = 0
        for (nas_ip, domain), stats in final_stats.items():
            DailyWebsiteStats.objects.update_or_create(
                date=target_date,
                nas_ip=nas_ip,
                domain=domain,
                defaults={
                    'visit_count': stats['visits'],
                    'unique_users': len(stats['users']),
                    'total_bytes': stats['bytes']
                }
            )
            save_count += 1

        self.stdout.write(self.style.SUCCESS(f"Finished. Saved {save_count} domain stats for {target_date}"))
