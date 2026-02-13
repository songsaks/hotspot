from .models import PendingUser

def pending_requests_count(request):
    if request.user.is_authenticated:
        try:
            count = PendingUser.objects.count()
            return {'pending_count': count}
        except:
            return {'pending_count': 0}
    return {}
