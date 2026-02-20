from .models import UserRouterAccess

def get_allowed_routers(user):
    """
    Returns a list of allowed router IPs for the given user.
    If user is superuser, returns None (meaning all).
    """
    if user.is_superuser:
        return None
    
    return list(UserRouterAccess.objects.filter(user=user).values_list('router_ip', flat=True))
