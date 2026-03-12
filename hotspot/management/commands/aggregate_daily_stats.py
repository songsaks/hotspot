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
        # 1. กำหนดวันที่ที่ต้องการสรุป (Default: เมื่อวานนี้)
        # เราสรุปยอดของวันวานเพื่อให้ได้ข้อมูลที่จบวันครบทั้ง 24 ชม.
        if options['date']:
            target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
        else:
            target_date = (datetime.now() - timedelta(days=1)).date()

        self.stdout.write(f"Aggregating stats for: {target_date}")

        # 2. Domain Mapping (ยุบรวมชื่อแบรนด์ยักษ์ใหญ่)
        DOMAIN_MAP = {
            # Google & YouTube
            'google.com': 'google.com', 'google.co.th': 'google.com', 
            '1e100.net': 'google.com', 'googleusercontent.com': 'google.com',
            'googleapis.com': 'google.com', 'gstatic.com': 'google.com',
            'youtube.com': 'youtube.com', 'googlevideo.com': 'youtube.com', 
            'ytimg.com': 'youtube.com', 'youtu.be': 'youtube.com',
            # Facebook & Instagram
            'facebook.com': 'facebook.com', 'fbcdn.net': 'facebook.com', 
            'facebook.net': 'facebook.com', 'fbsbx.com': 'facebook.com',
            'fb.me': 'facebook.com', 'fb.com': 'facebook.com', 'fb.gg': 'facebook.com',
            'messenger.com': 'facebook.com',
            'instagram.com': 'instagram.com', 'cdninstagram.com': 'instagram.com',
            'ig.me': 'instagram.com', 'igcdn.com': 'instagram.com',
            # TikTok
            'tiktok.com': 'tiktok.com', 'tiktokcdn.com': 'tiktok.com', 
            'tiktokv.com': 'tiktok.com', 'byteoversea.com': 'tiktok.com',
            'ibytedtos.com': 'tiktok.com', 'musical.ly': 'tiktok.com',
            'tiktokcdn-us.com': 'tiktok.com', 'snssdk.com': 'tiktok.com',
            'amemv.com': 'tiktok.com',
            # LINE
            'line.me': 'line.me', 'line-scdn.net': 'line.me', 
            'line-apps.com': 'line.me', 'naver.jp': 'line.me',
            'linecorp.com': 'line.me', 'line.naver.jp': 'line.me',
            # X / Twitter
            'x.com': 'x.com', 'twitter.com': 'x.com', 't.co': 'x.com', 'twimg.com': 'x.com',
            # E-Commerce
            'shopee.co.th': 'shopee.co.th', 'shopeemobile.com': 'shopee.co.th',
            'lazada.co.th': 'lazada.co.th',
            # Microsoft
            'microsoft.com': 'microsoft.com', 'live.com': 'microsoft.com',
            'office.com': 'microsoft.com', 'windows.net': 'microsoft.com',
            'microsoftonline.com': 'microsoft.com', 'msedge.net': 'microsoft.com',
            # Others
            'netflix.com': 'netflix.com', 'spotify.com': 'spotify.com',
            'apple.com': 'apple.com', 'cloudflare.com': 'cloudflare.com',
        }

        def map_domain(d):
            if not d: return d
            d = d.lower().strip()
            if d.startswith('www.'): d = d[4:]
            
            # 1. Direct match
            if d in DOMAIN_MAP: return DOMAIN_MAP[d]
            
            # 2. Subdomain match (e.g. abc.google.com -> google.com)
            for tech, human in DOMAIN_MAP.items():
                if d.endswith('.' + tech): return human
            return d

        # 3. ดึง Log ดิบเฉพาะของวันที่ต้องการ
        qs = TrafficLog.objects.filter(
            log_time__year=target_date.year,
            log_time__month=target_date.month,
            log_time__day=target_date.day
        )

        total_logs = qs.count()
        if total_logs == 0:
            self.stderr.write(f"No logs found for {target_date}")
            return

        # 4. รวมกลุ่มข้อมูลเบื้องต้นจาก Database (Group By NAS + Source + Dest IP)
        # ขั้นตอนนี้ช่วยลดข้อมูลจากล้านบรรทัดเหลือเพียงหลักร้อย/หลักพัน เพื่อรอการแปลง IP เป็นชื่อเว็บ
        ip_agg = list(qs.values('nas_ip', 'source_ip', 'destination_ip').annotate(
            visits=Count('id'),
            bytes=Sum('bytes_sent') + Sum('bytes_received')
        ).order_by('-visits')[:1000])

        # 5. การแปลง IP เป็นชื่อเว็บไซต์แบบขนาน (Parallel DNS Lookup)
        # เราใช้ ThreadPoolExecutor เพื่อให้พนักงานหลายคนช่วยกันถามชื่อเว็บไซต์พร้อมกัน (จบงานเร็วขึ้น 20 เท่า)
        # และใช้ระบบ Cache 2 ชั้น (RAM + Redis) เพื่อจดจำชื่อที่เคยถามไปแล้ว
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        unique_ips = list(set(item['destination_ip'] for item in ip_agg))
        ip_to_domain = {}
        
        def resolve_and_map(ip):
            hostname = reverse_dns_cached(ip)
            if hostname:
                domain = simplify_domain(hostname)
                return ip, map_domain(domain)
            return ip, None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(resolve_and_map, ip): ip for ip in unique_ips}
            for future in as_completed(futures):
                try:
                    ip, domain = future.result()
                    if domain: ip_to_domain[ip] = domain
                except: pass

        # 6. ประมวลผลและนับ Unique Users ในหน่วยความจำ
        # final_stats: { (nas_ip, domain): {visits, bytes, unique_users_set} }
        final_stats = {} 

        for item in ip_agg:
            nas_ip = item['nas_ip']
            ip = item['destination_ip']
            source_ip = item['source_ip']
            
            domain = ip_to_domain.get(ip)
            # ข้ามข้อมูลที่ไม่สามารถระบุชื่อเว็บไซต์ได้ (เพื่อความคลีนของรายงาน)
            if not domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                continue
            
            key = (nas_ip, domain)
            if key not in final_stats:
                final_stats[key] = {'visits': 0, 'bytes': 0, 'users': set()}
            
            final_stats[key]['visits'] += item['visits']
            final_stats[key]['bytes'] += (item['bytes'] or 0)
            final_stats[key]['users'].add(source_ip)

        # 7. บันทึกผลลัพธ์ลงตารางสรุป DailyWebsiteStats
        # เป็นการ "Extract" สาระสำคัญมาเก็บไว้ เพื่อให้ดูย้อนหลังได้ไม่จำกัดและโหลดเร็วมาก
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
