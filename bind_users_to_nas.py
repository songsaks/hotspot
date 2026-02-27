import os
import django
import sys

# Setup Django Environment
sys.path.append(r'd:\DjangoProjects\ninecom_hotspot')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ninecom_hotspot.settings')
django.setup()

from hotspot.models import UserNasAssignment, AdminActivityLog, UserProfileGroup
from hotspot.utils import get_allowed_routers
from django.contrib.auth.models import User
from django.db import connection

def fetch_all_users():
    with connection.cursor() as cursor:
        cursor.execute("SELECT DISTINCT username FROM radcheck WHERE attribute = 'Cleartext-Password'")
        return [row[0] for row in cursor.fetchall()]

def fetch_user_groups():
    with connection.cursor() as cursor:
        cursor.execute("SELECT username, groupname FROM radusergroup")
        return {row[0]: row[1] for row in cursor.fetchall()}

def run():
    print("Fetching all users in the system...")
    all_users = fetch_all_users()
    
    # Track who should be assigned to whom
    user_to_admin = {}
    
    print("1. Checking AdminActivityLogs...")
    # Map target_user -> admin_user from activity logs
    for log in AdminActivityLog.objects.all():
        if log.target in all_users:
            user_to_admin[log.target] = log.admin_user
            
    print("2. Checking User Profiles as fallback...")
    user_groups = fetch_user_groups()
    group_creators = {
        group.groupname: group.created_by.username
        for group in UserProfileGroup.objects.exclude(created_by__isnull=True)
    }
    
    for username, groupname in user_groups.items():
        if username in all_users and username not in user_to_admin:
            # If we don't know the creator from logs, maybe we know who created their profile group?
            if groupname in group_creators:
                user_to_admin[username] = group_creators[groupname]

    print(f"Calculated admins for {len(user_to_admin)} / {len(all_users)} users.")
    
    assignments_created = 0
    
    # Process assignments
    admin_routers_cache = {}
    
    for target_user, admin_username in user_to_admin.items():
        # Get routers for this admin
        if admin_username not in admin_routers_cache:
            try:
                admin_user = User.objects.get(username=admin_username)
                admin_routers_cache[admin_username] = get_allowed_routers(admin_user)
            except User.DoesNotExist:
                admin_routers_cache[admin_username] = None
                
        allowed_routers = admin_routers_cache[admin_username]
        
        if allowed_routers:
            for router_ip in allowed_routers:
                _, created = UserNasAssignment.objects.get_or_create(
                    username=target_user,
                    nasipaddress=router_ip
                )
                if created:
                    assignments_created += 1

    print(f"\nPhase 2 Migration complete! Assigned {assignments_created} missing user-to-router links.")

if __name__ == '__main__':
    run()
