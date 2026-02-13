from django.core.management.base import BaseCommand
from django.db import connection
from datetime import datetime

class Command(BaseCommand):
    help = 'Automatically cleanup expired hotspot vouchers starters with a specific prefix'

    def add_arguments(self, parser):
        # Forced to provide a prefix to be safe
        parser.add_argument('--prefix', type=str, help='Prefix of usernames to cleanup', default='VIP')

    def handle(self, *args, **options):
        prefix = options['prefix']
        self.stdout.write(f"[{datetime.now()}] Starting cleanup for prefix: {prefix}...")
        
        with connection.cursor() as cursor:
            # 1. Identify users who finished sessions AND start with the prefix
            cursor.execute("""
                SELECT DISTINCT username FROM radacct 
                WHERE acctstoptime IS NOT NULL AND username LIKE %s
            """, [f"{prefix}%"])
            expired_users = [row[0] for row in cursor.fetchall()]

            if not expired_users:
                self.stdout.write(self.style.SUCCESS(f"No expired sessions found for '{prefix}'. Skipping."))
                return

            count = len(expired_users)
            format_strings = ','.join(['%s'] * count)
            
            try:
                # 2. Delete from radusergroup
                cursor.execute(f"DELETE FROM radusergroup WHERE username IN ({format_strings})", expired_users)
                # 3. Delete from radcheck
                cursor.execute(f"DELETE FROM radcheck WHERE username IN ({format_strings})", expired_users)
                
                self.stdout.write(self.style.SUCCESS(f"Successfully removed {count} expired records (Prefix: {prefix})."))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error during cleanup: {str(e)}"))

        self.stdout.write(f"[{datetime.now()}] Cleanup complete.")
