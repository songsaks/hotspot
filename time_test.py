import os, django, sys, time
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from hotspot.models import Radacct
from hotspot.traffic_models import TrafficLog
from django.db import connection

def timing(f):
    def wrap(*args, **kw):
        time1 = time.time()
        ret = f(*args, **kw)
        time2 = time.time()
        print(f'{f.__name__} took {(time2-time1)*1000.0:.3f} ms')
        return ret
    return wrap

@timing
def step1():
    print("Testing routers distinct...")
    qs = TrafficLog.objects.using('default').exclude(nas_ip__isnull=True).exclude(nas_ip='').values_list('nas_ip', flat=True).distinct().order_by('nas_ip')
    return list(qs)

@timing
def step2():
    print("Testing base queryset execution...")
    qs = TrafficLog.objects.using('default').all().order_by('-id')[:50]
    return list(qs)

@timing
def step3(logs):
    print("Testing lookup active sessions...")
    from hotspot.views_traffic import lookup_active_sessions_for_logs
    return lookup_active_sessions_for_logs(logs)

@timing
def step4(logs):
    print("Testing enrich...")
    from hotspot.views_traffic import enrich_logs
    return enrich_logs(logs)

from hotspot.models import Nas
@timing
def check_nas():
    print("Checking NAS distinct via Nas table...")
    qs = Nas.objects.using('default').values_list('nasname', flat=True)
    return list(qs)

routers = step1()
check_nas()
logs = step2()
active = step3(logs)
step4(logs)
