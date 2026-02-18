from django.shortcuts import render
from django.db.models import Q
from django.core.paginator import Paginator
from django.http import HttpResponse
import csv
from datetime import datetime
from django.contrib.auth.decorators import login_required
from .models import Radacct

def download_session_csv(queryset):
    response = HttpResponse(content_type='text/csv')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    response['Content-Disposition'] = f'attachment; filename="session_logs_{timestamp}.csv"'
    response.write(u'\ufeff'.encode('utf8')) # BOM

    writer = csv.writer(response)
    writer.writerow(['StartTime', 'StopTime', 'Username', 'IP Address', 'MAC Address', 'Session Time', 'Upload (Bytes)', 'Download (Bytes)', 'Terminate Cause'])

    for s in queryset:
        # Avoid potential None values
        start_time = s.acctstarttime.strftime("%Y-%m-%d %H:%M:%S") if s.acctstarttime else ""
        stop_time = s.acctstoptime.strftime("%Y-%m-%d %H:%M:%S") if s.acctstoptime else ""

        writer.writerow([
            start_time, 
            stop_time, 
            s.username, 
            s.framedipaddress, 
            s.callingstationid,
            s.acctsessiontime,
            s.acctinputoctets,
            s.acctoutputoctets,
            s.acctterminatecause or 'N/A'
        ])
    return response

@login_required
def user_session_search(request):
    """
    Search session history by Username, IP, or MAC.
    Includes Pagination and Export to CSV.
    """
    query = request.GET.get('q', '').strip()
    export = request.GET.get('export', '')

    sessions_list = Radacct.objects.none() # Default empty

    if query:
        # Search match: username OR IP OR MAC
        sessions_list = Radacct.objects.filter(
            Q(username__icontains=query) | 
            Q(framedipaddress__icontains=query) | 
            Q(callingstationid__icontains=query)
        ).order_by('-acctstarttime')

        # Handle CSV Export if 'export=csv' is present in URL
        if export == 'csv':
            return download_session_csv(sessions_list)

    # Note: If no query, we show nothing or empty table to prompt search first.
    # Pagination
    paginator = Paginator(sessions_list, 20) # Show 20 contacts per page.
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'hotspot/session_search.html', {
        'page_obj': page_obj,
        'query': query
    })
