from .models import UserRouterAccess, Radacct, AdminActivityLog

def get_allowed_routers(user):
    """
    Returns a list of allowed router IPs for the given user.
    If user is superuser, returns None (meaning all).
    """
    if user.is_superuser:
        return None
    
    return list(UserRouterAccess.objects.filter(user=user).values_list('router_ip', flat=True))

def is_authorized_to_manage_user(admin_user, target_username):
    """
    Checks if the admin_user has permission to manage (edit/delete/assign) the target_username.
    """
    if admin_user.is_superuser:
        return True
        
    allowed_routers = get_allowed_routers(admin_user)
    
    # 1. Check if user ever connected to allowed routers
    # Note: If allowed_routers is empty list, this check is skipped (no access via router)
    if allowed_routers:
        if Radacct.objects.filter(username=target_username, nasipaddress__in=allowed_routers).exists():
            return True
            
    # 2. Check if user was created/managed by this admin
    if AdminActivityLog.objects.filter(admin_user=admin_user.username, target=target_username).exists():
        return True
        
    return False
