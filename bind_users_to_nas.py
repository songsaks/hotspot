import os
import django
import sys

# Setup Django Environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.db import connection, transaction
from hotspot.models import Radcheck

def run_binding():
    print("Starting NAS-IP-Address Binding Script...")
    
    with connection.cursor() as cursor:
        # Step 1: Find users who DO NOT have a NAS-IP-Address assigned yet
        # But HAVE an active/historical session in radacct
        
        # We query for users and their most recent NAS IP
        query = """
            SELECT r.username, 
                   (SELECT a.nasipaddress 
                    FROM radacct a 
                    WHERE a.username = r.username 
                    ORDER BY a.acctstarttime DESC 
                    LIMIT 1) as latest_nas
            FROM (SELECT DISTINCT username FROM radcheck WHERE attribute = 'Cleartext-Password') r
            WHERE NOT EXISTS (
                SELECT 1 FROM radcheck rc 
                WHERE rc.username = r.username AND rc.attribute = 'NAS-IP-Address'
            )
            HAVING latest_nas IS NOT NULL
        """
        
        cursor.execute(query)
        unbound_users = cursor.fetchall()
        
        if not unbound_users:
            print("No new users to bind. Everyone is already protected or hasn't logged in yet.")
            return

        print(f"Found {len(unbound_users)} unbound users with login history. Binding them now...")
        
        # Step 2: Insert the NAS-IP-Address rule
        added_count = 0
        with transaction.atomic():
            for username, latest_nas in unbound_users:
                # Add the lock to radcheck
                Radcheck.objects.create(
                    username=username,
                    attribute='NAS-IP-Address',
                    op='==',
                    value=latest_nas
                )
                added_count += 1
                
        print(f"Successfully bound {added_count} users to their respective routers.")

if __name__ == '__main__':
    run_binding()
