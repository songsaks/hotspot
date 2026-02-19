from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.db import connection
from django.contrib.auth.decorators import login_required
import pandas as pd
import random
import string
import logging
import os
import csv
from django.conf import settings
from django.http import HttpResponse
from datetime import datetime
from datetime import time  # Added import
from .models import Radcheck, PendingUser, ApprovedUser, AdminActivityLog
from .models import Radcheck, PendingUser, ApprovedUser, AdminActivityLog, Radacct
from .traffic_models import TrafficLog
from .forms import HotspotUserForm, UserImportForm
import json
from django.db.models import Count, Sum, F, FloatField, ExpressionWrapper, Q, Value
from django.db.models.functions import TruncDate, ExtractHour, Coalesce
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger('hotspot')

from django.core.paginator import Paginator
from django.db.models import Q
import csv

@login_required
def dashboard(request):
    # Summary Statistics
    total_users = Radcheck.objects.count()
    online_users = Radacct.objects.filter(acctstoptime__isnull=True).count()
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    todays_active = Radacct.objects.filter(acctstarttime__gte=today_start).values('username').distinct().count()
    pending_requests = PendingUser.objects.count()

    context = {
        'total_users': total_users,
        'online_users': online_users,
        'todays_active': todays_active,
        'pending_requests': pending_requests
    }
    return render(request, 'hotspot/dashboard.html', context)

# ... existing code ...

@login_required
def registration_requests(request):
    pending_users = PendingUser.objects.all().order_by('-created_at')
    
    # Detect potential duplicates
    # 1. Same full_name or phone appearing multiple times in pending
    from django.db.models import Count
    dup_names = set(
        PendingUser.objects.exclude(full_name='').exclude(full_name__isnull=True)
        .values('full_name').annotate(cnt=Count('id')).filter(cnt__gt=1)
        .values_list('full_name', flat=True)
    )
    dup_phones = set(
        PendingUser.objects.exclude(phone='').exclude(phone__isnull=True)
        .values('phone').annotate(cnt=Count('id')).filter(cnt__gt=1)
        .values_list('phone', flat=True)
    )
    
    # 2. Check if username/phone already exists in approved users
    existing_usernames = set(
        Radcheck.objects.filter(attribute='Cleartext-Password')
        .values_list('username', flat=True)
    )
    existing_phones = set(
        ApprovedUser.objects.exclude(phone='').exclude(phone__isnull=True)
        .values_list('phone', flat=True)
    )
    
    # Mark each pending user with duplicate flags
    for user in pending_users:
        user.is_dup_name = user.full_name and user.full_name in dup_names
        user.is_dup_phone = user.phone and user.phone in dup_phones
        user.already_exists = user.username in existing_usernames
        user.phone_exists = user.phone and user.phone in existing_phones
    
    # Get profiles for assignment
    with connection.cursor() as cursor:
        cursor.execute("SELECT DISTINCT groupname FROM radgroupreply")
        profiles = dictfetchall(cursor)
        
    return render(request, 'hotspot/registration_requests.html', {
        'pending_users': pending_users,
        'profiles': profiles
    })

@login_required
def approve_user(request, pk):
    pending = get_object_or_404(PendingUser, pk=pk)
    if request.method == 'POST':
        groupname = request.POST.get('groupname')
        if groupname:
            # 1. Create Radcheck entry
            Radcheck.objects.update_or_create(
                username=pending.username,
                attribute='Cleartext-Password',
                defaults={'op': ':=', 'value': pending.password}
            )
            
            # 2. Assign to group
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM radusergroup WHERE username = %s", [pending.username])
                cursor.execute(
                    "INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)",
                    [pending.username, groupname, 1]
                )
            
            # 3. Save to ApprovedUser for tracking
            ApprovedUser.objects.update_or_create(
                username=pending.username,
                defaults={
                    'full_name': pending.full_name,
                    'phone': pending.phone
                }
            )
            
            # 4. Remove from pending
            pending.delete()
            
            # Record log
            AdminActivityLog.objects.create(
                admin_user=request.user.username,
                action='Approve User',
                target=pending.username,
                details=f"Approved and assigned to profile: {groupname}"
            )
            
            messages.success(request, f"User '{pending.username}' approved and assigned to '{groupname}'.")
        else:
            messages.error(request, "Please select a profile.")
    return redirect('registration_requests')

@login_required
def reject_user(request, pk):
    pending = get_object_or_404(PendingUser, pk=pk)
    username = pending.username
    pending.delete()
    
    # Also ensure no residue is left in ApprovedUser if they were approved before
    ApprovedUser.objects.filter(username=username).delete()
    
    # Record log
    AdminActivityLog.objects.create(
        admin_user=request.user.username,
        action='Reject Registration',
        target=username,
        details="Registration request was rejected by administrator"
    )
    
    messages.warning(request, f"Registration request for '{username}' has been rejected.")
    return redirect('registration_requests')

# This view is PUBLIC (no login required) - Called by Mikrotik
def self_register(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        full_name = request.POST.get('full_name', '').strip()
        phone = request.POST.get('phone', '').strip()
        
        if not username or not password:
            messages.error(request, "Username and Password are required.")
            return render(request, 'hotspot/self_register.html')
            
        # Check if username already exists in any of our 3 user tables (Case-Insensitive)
        username_exists = (
            Radcheck.objects.filter(username__iexact=username).exists() or 
            PendingUser.objects.filter(username__iexact=username).exists() or
            ApprovedUser.objects.filter(username__iexact=username).exists()
        )
        
        if username_exists:
            messages.error(request, "This username is already taken or pending approval.")
            return render(request, 'hotspot/self_register.html')
            
        PendingUser.objects.create(
            username=username,
            password=password,
            full_name=full_name,
            phone=phone
        )
        return render(request, 'hotspot/registration_success.html', {'username': username})
        
    return render(request, 'hotspot/self_register.html')

@login_required
def member_directory(request):
    members = ApprovedUser.objects.all().order_by('-approved_at')
    return render(request, 'hotspot/member_directory.html', {'members': members})

def dictfetchall(cursor):
    "Return all rows from a cursor as a dict"
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

@login_required
def user_autocomplete(request):
    term = request.GET.get('term', '')
    users = []
    if term:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username FROM radcheck WHERE username LIKE %s LIMIT 10", [f'%{term}%'])
            users = [row[0] for row in cursor.fetchall()]
    return JsonResponse(users, safe=False)

@login_required
def user_list(request):
    search_query = request.GET.get('search', '').strip()
    with connection.cursor() as cursor:
        if search_query:
            cursor.execute("""
                SELECT 
                    rc.id, 
                    rc.username, 
                    rc.value as password, 
                    rug.groupname, 
                    au.id as is_self_reg,
                    (SELECT 1 FROM radcheck rc2 WHERE rc2.username = rc.username AND rc2.attribute = 'Auth-Type' AND rc2.value = 'Reject' LIMIT 1) as is_disabled
                FROM radcheck rc
                LEFT JOIN radusergroup rug ON rc.username = rug.username
                LEFT JOIN approved_users au ON rc.username = au.username
                WHERE rc.attribute = 'Cleartext-Password' AND rc.username LIKE %s
                ORDER BY rc.id DESC
            """, [f'%{search_query}%'])
        else:
            cursor.execute("""
                SELECT 
                    rc.id, 
                    rc.username, 
                    rc.value as password, 
                    rug.groupname, 
                    au.id as is_self_reg,
                    (SELECT 1 FROM radcheck rc2 WHERE rc2.username = rc.username AND rc2.attribute = 'Auth-Type' AND rc2.value = 'Reject' LIMIT 1) as is_disabled
                FROM radcheck rc
                LEFT JOIN radusergroup rug ON rc.username = rug.username
                LEFT JOIN approved_users au ON rc.username = au.username
                WHERE rc.attribute = 'Cleartext-Password'
                ORDER BY rc.id DESC LIMIT 100
            """)
        
        users = dictfetchall(cursor)
        cursor.execute("SELECT DISTINCT groupname FROM radgroupreply")
        profiles = dictfetchall(cursor)

    return render(request, 'hotspot/user_list.html', {
        'users': users,
        'profiles': profiles,
        'search_query': search_query
    })

@login_required
def reset_password(request, username):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        if new_password:
            Radcheck.objects.filter(username=username, attribute='Cleartext-Password').update(value=new_password)
            
            AdminActivityLog.objects.create(
                admin_user=request.user.username,
                action='Reset Password',
                target=username,
                details="Password updated by administrator"
            )
            
            messages.success(request, f"Password for user '{username}' has been reset.")
        else:
            messages.error(request, "Password cannot be empty.")
    return redirect('user_list')

@login_required
def toggle_user_status(request, username):
    # Check if currently disabled
    is_disabled = Radcheck.objects.filter(username=username, attribute='Auth-Type', value='Reject').exists()
    
    if is_disabled:
        # Enable: Remove Reject attribute
        Radcheck.objects.filter(username=username, attribute='Auth-Type', value='Reject').delete()
        messages.success(request, f"User '{username}' has been enabled.")
    else:
        # Disable: Add Reject attribute
        Radcheck.objects.create(
            username=username,
            attribute='Auth-Type',
            op=':=',
            value='Reject'
        )
        messages.warning(request, f"User '{username}' has been disabled.")
        
    AdminActivityLog.objects.create(
        admin_user=request.user.username,
        action='Toggle Status',
        target=username,
        details=f"User is now {'Enabled' if is_disabled else 'Disabled'}"
    )
        
    return redirect('user_list')

@login_required
def active_sessions(request):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT radacctid, username, framedipaddress, nasipaddress, 
                   acctstarttime, acctsessiontime, acctinputoctets, acctoutputoctets, callingstationid
            FROM radacct 
            WHERE acctstoptime IS NULL 
            ORDER BY acctstarttime DESC
        """)
        active_users = dictfetchall(cursor)
    
    return render(request, 'hotspot/active_sessions.html', {'sessions': active_users})

@login_required
def usage_report(request):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                username, 
                COUNT(*) as total_sessions,
                SUM(acctsessiontime) as total_time,
                SUM(acctinputoctets) as total_download,
                SUM(acctoutputoctets) as total_upload,
                MAX(acctstarttime) as last_connected
            FROM radacct
            GROUP BY username
            ORDER BY last_connected DESC
        """)
        usage_data = dictfetchall(cursor)
    
    return render(request, 'hotspot/usage_report.html', {
        'usage_data': usage_data,
        'title': 'Authentication Log (Full History)'
    })

@login_required
def compliance_report(request):
    nas_ip = request.GET.get('nas_ip', '').strip()
    search_query = request.GET.get('search', '').strip()
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    
    with connection.cursor() as cursor:
        # Get available NAS IPs for dropdown
        cursor.execute("SELECT DISTINCT nasipaddress FROM radacct ORDER BY nasipaddress")
        available_nas = [row[0] for row in cursor.fetchall()]
        
        # Aggregation: Monthly usage per user
        monthly_sql = """
            SELECT 
                username, 
                COUNT(*) as sessions,
                SUM(acctsessiontime) as total_time,
                SUM(acctinputoctets) as total_in,
                SUM(acctoutputoctets) as total_out
            FROM radacct
            WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 1 MONTH)
        """
        monthly_params = []
        if nas_ip and nas_ip != 'all':
            monthly_sql += " AND nasipaddress = %s"
            monthly_params.append(nas_ip)
        monthly_sql += " GROUP BY username ORDER BY total_in DESC LIMIT 10"
        cursor.execute(monthly_sql, monthly_params)
        monthly_stats = dictfetchall(cursor)

        # Main Log Query (Compliance)
        sql = """
            SELECT 
                acctstarttime, acctstoptime, username, callingstationid as mac, 
                framedipaddress as ip, acctsessiontime, acctinputoctets as download, 
                acctoutputoctets as upload, nasipaddress
            FROM radacct
            WHERE 1=1
        """
        params = []
        
        if nas_ip and nas_ip != 'all':
            sql += " AND nasipaddress = %s"
            params.append(nas_ip)
        
        if start_date:
            sql += " AND acctstarttime >= %s"
            params.append(start_date)
        if end_date:
            sql += " AND acctstarttime <= %s"
            params.append(f"{end_date} 23:59:59")
            
        if search_query:
            sql += " AND (username LIKE %s OR callingstationid LIKE %s OR framedipaddress LIKE %s)"
            params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
        
        sql += " ORDER BY acctstarttime DESC LIMIT 1000"
        cursor.execute(sql, params)
        logs = dictfetchall(cursor)

    return render(request, 'hotspot/compliance_report.html', {
        'logs': logs,
        'monthly_stats': monthly_stats,
        'search_query': search_query,
        'current_nas': nas_ip,
        'start_date': start_date,
        'end_date': end_date,
        'available_nas': available_nas,
    })

@login_required
def export_compliance_csv(request):
    nas_ip = request.GET.get('nas_ip', '10.1.1.2')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="hotspot_logs_{datetime.now().strftime("%Y%m%d")}.csv"'
    response.write(u'\ufeff'.encode('utf8')) # BOM for Thai language in Excel

    writer = csv.writer(response)
    writer.writerow(['DateTime Start', 'DateTime Stop', 'Username', 'MAC Address', 'IP Address', 'Session Time (s)', 'Download (Bytes)', 'Upload (Bytes)'])

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT acctstarttime, acctstoptime, username, callingstationid, framedipaddress, 
                   acctsessiontime, acctinputoctets, acctoutputoctets 
            FROM radacct WHERE nasipaddress = %s ORDER BY acctstarttime DESC LIMIT 5000
        """, [nas_ip])
        for row in cursor.fetchall():
            writer.writerow(row)
    
    return response

@login_required
def admin_logs(request):
    # Admin Activity Logs
    activity_logs = AdminActivityLog.objects.all()[:200]
    
    # System Logs from file
    system_logs = []
    log_file_path = os.path.join(settings.LOGS_DIR, 'hotspot_system.log')
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                # Get last 100 lines
                system_logs = f.readlines()[-100:]
                system_logs.reverse()
        except Exception as e:
            system_logs = [f"Error reading system logs: {str(e)}"]

    return render(request, 'hotspot/admin_logs.html', {
        'activity_logs': activity_logs,
        'system_logs': system_logs
    })

@login_required
def manage_vouchers(request):
    with connection.cursor() as cursor:
        if request.method == 'POST' and 'generate' in request.POST:
            prefix = request.POST.get('prefix', 'VIP').strip()
            count = int(request.POST.get('count', '1'))
            groupname = request.POST.get('groupname')
            
            created_vouchers = []
            for _ in range(count):
                random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
                username = f"{prefix}{random_str}"
                password = ''.join(random.choices(string.digits, k=4))
                
                Radcheck.objects.create(username=username, attribute='Cleartext-Password', op=':=', value=password)
                cursor.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)", [username, groupname, 1])
                created_vouchers.append({'user': username, 'pass': password})
            
            messages.success(request, f"Generated {count} temporary tickets for {groupname}")
            return render(request, 'hotspot/voucher_print.html', {'vouchers': created_vouchers, 'profile': groupname})

        # Cleanup logic
        if 'cleanup' in request.GET:
            prefix = request.GET.get('prefix', '').strip()
            if len(prefix) < 2:
                messages.error(request, "Please provide a specific prefix (at least 2 characters) to clean up.")
            else:
                cursor.execute("""
                    SELECT DISTINCT username FROM radacct 
                    WHERE acctstoptime IS NOT NULL AND username LIKE %s
                """, [f"{prefix}%"])
                expired_users = [row[0] for row in cursor.fetchall()]

                if expired_users:
                    format_strings = ','.join(['%s'] * len(expired_users))
                    cursor.execute(f"DELETE FROM radusergroup WHERE username IN ({format_strings})", expired_users)
                    cursor.execute(f"DELETE FROM radcheck WHERE username IN ({format_strings})", expired_users)
                    messages.info(request, f"Cleaned up {len(expired_users)} expired tickets starting with '{prefix}'.")
                else:
                    messages.info(request, f"No expired tickets found starting with '{prefix}'.")
            return redirect('manage_vouchers')

        # Get existing vouchers and their status
        # We define vouchers as users having the current prefix in the search (default 'VIP')
        current_prefix = request.GET.get('view_prefix', 'VIP')
        cursor.execute("""
            SELECT rc.username, rug.groupname,
                   (SELECT MAX(acctstoptime) FROM radacct ra WHERE ra.username = rc.username) as stop_time,
                   (SELECT COUNT(*) FROM radacct ra WHERE ra.username = rc.username AND ra.acctstoptime IS NULL) as is_online
            FROM radcheck rc
            JOIN radusergroup rug ON rc.username = rug.username
            WHERE rc.username LIKE %s
            ORDER BY rc.id DESC
        """, [f"{current_prefix}%"])
        vouchers_list = dictfetchall(cursor)

        cursor.execute("SELECT DISTINCT groupname FROM radgroupreply")
        profiles = dictfetchall(cursor)

    return render(request, 'hotspot/vouchers.html', {
        'profiles': profiles, 
        'vouchers_list': vouchers_list,
        'current_prefix': current_prefix
    })

@login_required
def kick_user(request, username):
    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE radacct 
            SET acctstoptime = NOW(), 
                acctterminatecause = 'Admin-Reset'
            WHERE username = %s AND acctstoptime IS NULL
        """, [username])
    messages.success(request, f"User '{username}' disconnected.")
    return redirect('active_sessions')

@login_required
def user_create(request):
    if request.method == 'POST':
        form = HotspotUserForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'User created successfully!')
            return redirect('user_list')
    else:
        form = HotspotUserForm()
    return render(request, 'hotspot/user_form.html', {'form': form})

@login_required
def user_import(request):
    # Fetch existing profiles for the dropdown
    with connection.cursor() as cursor:
        cursor.execute("SELECT DISTINCT groupname FROM radgroupreply")
        profiles = [ (row[0], row[0]) for row in cursor.fetchall() ]

    if request.method == 'POST':
        form = UserImportForm(request.POST, request.FILES, profile_choices=profiles)
        if form.is_valid():
            excel_file = request.FILES['excel_file']
            selected_profile = form.cleaned_data.get('profile')
            
            try:
                # Read the excel file
                df = pd.read_excel(excel_file)
                
                # Logic: Expecting columns 'username' and 'password'
                if 'username' not in df.columns or 'password' not in df.columns:
                    messages.error(request, "Excel file must have 'username' and 'password' columns.")
                    return render(request, 'hotspot/user_import.html', {'form': form})

                count = 0
                imported_usernames = []
                for index, row in df.iterrows():
                    username = str(row['username']).strip()
                    password = str(row['password']).strip()
                    
                    if username and password:
                        # Create or update Radcheck entry
                        Radcheck.objects.update_or_create(
                            username=username,
                            attribute='Cleartext-Password',
                            defaults={'op': ':=', 'value': password}
                        )
                        imported_usernames.append(username)
                        count += 1
                
                # Assign to profile if selected
                if selected_profile and imported_usernames:
                    with connection.cursor() as cursor:
                        for username in imported_usernames:
                            # Check if assignment exists
                            cursor.execute("SELECT username FROM radusergroup WHERE username = %s", [username])
                            if cursor.fetchone():
                                cursor.execute(
                                    "UPDATE radusergroup SET groupname = %s WHERE username = %s",
                                    [selected_profile, username]
                                )
                            else:
                                cursor.execute(
                                    "INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)",
                                    [username, selected_profile, 1]
                                )
                
                messages.success(request, f'Successfully imported {count} users.')
                return redirect('user_list')
            except Exception as e:
                messages.error(request, f'Error processing file: {str(e)}')
    else:
        form = UserImportForm(profile_choices=profiles)
    
    return render(request, 'hotspot/user_import.html', {'form': form})

@login_required
def manage_profiles(request):
    with connection.cursor() as cursor:
        if request.method == 'POST' and 'create_profile' in request.POST:
            group_name = request.POST.get('group_name')
            dl_speed = request.POST.get('download_speed', '').strip()
            ul_speed = request.POST.get('upload_speed', '').strip()
            timeout_hours = request.POST.get('session_timeout', '24')
            sim_sessions = request.POST.get('simultaneous_sessions', '1')
            idle_timeout = request.POST.get('idle_timeout', '10')
            data_quota_mb = request.POST.get('data_quota', '').strip()

            if dl_speed.isdigit(): dl_speed += 'M'
            if ul_speed.isdigit(): ul_speed += 'M'
            rate_limit = f"{ul_speed}/{dl_speed}"
            
            try:
                cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [group_name, 'Mikrotik-Rate-Limit', ':=', rate_limit])
                cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [group_name, 'Session-Timeout', ':=', str(int(timeout_hours)*3600)])
                cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [group_name, 'Simultaneous-Use', ':=', sim_sessions])
                cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [group_name, 'Idle-Timeout', ':=', str(int(idle_timeout)*60)])
                if data_quota_mb and data_quota_mb.isdigit():
                    bytes_quota = int(data_quota_mb) * 1024 * 1024
                    cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [group_name, 'Mikrotik-Total-Limit', ':=', str(bytes_quota)])
                messages.success(request, f"Profile '{group_name}' created.")
            except Exception as e:
                messages.error(request, f"Error: {str(e)}")
            return redirect('manage_profiles')

        cursor.execute("SELECT groupname, attribute, value FROM radgroupreply")
        reply_rows = dictfetchall(cursor)
        profiles_dict = {}
        for row in reply_rows:
            gn, attr, val = row['groupname'], row['attribute'], row['value']
            if gn not in profiles_dict:
                profiles_dict[gn] = {'groupname': gn, 'speed': 'N/A', 'timeout': 'N/A', 'sessions': '1', 'idle': 'N/A', 'quota': 'Unlimited'}
            if attr == 'Mikrotik-Rate-Limit': profiles_dict[gn]['speed'] = val
            elif attr == 'Session-Timeout': profiles_dict[gn]['timeout'] = int(val) // 3600
            elif attr == 'Simultaneous-Use': profiles_dict[gn]['sessions'] = val
            elif attr == 'Idle-Timeout': profiles_dict[gn]['idle'] = int(val) // 60
            elif attr == 'Mikrotik-Total-Limit': profiles_dict[gn]['quota'] = f"{int(val) // (1024*1024)} MB"
        
        profiles = list(profiles_dict.values())
        cursor.execute("SELECT groupname, username FROM radusergroup")
        user_group_rows = dictfetchall(cursor)
        group_users = {}
        for row in user_group_rows:
            gn, un = row['groupname'], row['username']
            if gn not in group_users: group_users[gn] = []
            group_users[gn].append(un)
        for p in profiles: p['user_list'] = group_users.get(p['groupname'], [])
        cursor.execute("SELECT DISTINCT username FROM radcheck")
        users = dictfetchall(cursor)

    return render(request, 'hotspot/profile_manager.html', {'profiles': profiles, 'users': users})

@login_required
def edit_profile(request, groupname):
    with connection.cursor() as cursor:
        if request.method == 'POST':
            dl_speed = request.POST.get('download_speed', '').strip()
            ul_speed = request.POST.get('upload_speed', '').strip()
            timeout_hours = request.POST.get('session_timeout', '24')
            sim_sessions = request.POST.get('simultaneous_sessions', '1')
            idle_timeout = request.POST.get('idle_timeout', '10')
            data_quota_mb = request.POST.get('data_quota', '').strip()
            
            if dl_speed.isdigit(): dl_speed += 'M'
            if ul_speed.isdigit(): ul_speed += 'M'
            rate_limit = f"{ul_speed}/{dl_speed}"
            
            try:
                cursor.execute("UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = 'Mikrotik-Rate-Limit'", [rate_limit, groupname])
                cursor.execute("UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = 'Session-Timeout'", [str(int(timeout_hours)*3600), groupname])
                for attr, val in [('Simultaneous-Use', sim_sessions), ('Idle-Timeout', str(int(idle_timeout)*60))]:
                    cursor.execute("SELECT id FROM radgroupreply WHERE groupname = %s AND attribute = %s", [groupname, attr])
                    if cursor.fetchone():
                        cursor.execute("UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = %s", [val, groupname, attr])
                    else:
                        cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [groupname, attr, ':=', val])
                
                cursor.execute("SELECT id FROM radgroupreply WHERE groupname = %s AND attribute = 'Mikrotik-Total-Limit'", [groupname])
                exists = cursor.fetchone()
                if data_quota_mb and data_quota_mb.isdigit():
                    val = str(int(data_quota_mb) * 1024 * 1024)
                    if exists: cursor.execute("UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = 'Mikrotik-Total-Limit'", [val, groupname])
                    else: cursor.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)", [groupname, 'Mikrotik-Total-Limit', ':=', val])
                elif exists:
                    cursor.execute("DELETE FROM radgroupreply WHERE groupname = %s AND attribute = 'Mikrotik-Total-Limit'", [groupname])

                messages.success(request, f"Profile '{groupname}' updated.")
            except Exception as e:
                messages.error(request, f"Error: {str(e)}")
            return redirect('manage_profiles')

        cursor.execute("SELECT attribute, value FROM radgroupreply WHERE groupname = %s", [groupname])
        rows = dictfetchall(cursor)
        data = {'groupname': groupname, 'dl': '', 'ul': '', 'timeout': '24', 'sessions': '1', 'idle': '10', 'quota': ''}
        for row in rows:
            attr, val = row['attribute'], row['value']
            if attr == 'Mikrotik-Rate-Limit':
                if '/' in val: data['ul'], data['dl'] = val.split('/')
                else: data['dl'] = val
            elif attr == 'Session-Timeout': data['timeout'] = int(val) // 3600
            elif attr == 'Simultaneous-Use': data['sessions'] = val
            elif attr == 'Idle-Timeout': data['idle'] = int(val) // 60
            elif attr == 'Mikrotik-Total-Limit': data['quota'] = int(val) // (1024 * 1024)
    
    return render(request, 'hotspot/profile_edit.html', {'data': data})

@login_required
def delete_profile(request, groupname):
    """Delete a profile group and all associated rules with password confirmation."""
    if request.method == 'POST':
        password = request.POST.get('confirm_password')
        target_password = os.getenv('BULK_DELETE_PASSWORD', 'super')
        
        if password != target_password:
            messages.error(request, "Incorrect super password. Profile deletion aborted.")
            return redirect('manage_profiles')
            
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM radgroupreply WHERE groupname = %s", [groupname])
            cursor.execute("DELETE FROM radusergroup WHERE groupname = %s", [groupname])
        
        messages.success(request, f"Profile '{groupname}' has been deleted successfully.")
    else:
        messages.error(request, "Invalid request method for profile deletion.")
        
    return redirect('manage_profiles')

@login_required
def remove_user_from_group(request, username):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM radusergroup WHERE username = %s", [username])
    messages.success(request, f"User '{username}' removed from group.")
    return redirect('manage_profiles')

@login_required
def assign_user_group(request):
    if request.method == 'POST':
        username, groupname = request.POST.get('username'), request.POST.get('groupname')
        with connection.cursor() as cursor:
            cursor.execute("SELECT username FROM radusergroup WHERE username = %s", [username])
            if cursor.fetchone():
                cursor.execute("UPDATE radusergroup SET groupname = %s WHERE username = %s", [groupname, username])
            else:
                cursor.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)", [username, groupname, 1])
        messages.success(request, f"User '{username}' assigned to '{groupname}'")
    return redirect(request.META.get('HTTP_REFERER', 'manage_profiles'))

@login_required
def delete_user(request, username):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM radcheck WHERE username = %s", [username])
        cursor.execute("DELETE FROM radusergroup WHERE username = %s", [username])
        cursor.execute("DELETE FROM approved_users WHERE username = %s", [username])
    messages.success(request, f"User '{username}' deleted.")
    return redirect('user_list')

@login_required
def bulk_delete_users(request):
    """Bulk delete users by manual selection, or by prefix and length."""
    if request.method == 'POST':
        password = request.POST.get('confirm_password')
        target_password = os.getenv('BULK_DELETE_PASSWORD', 'super')
        
        if password != target_password:
            messages.error(request, "Incorrect super password. Bulk delete aborted.")
            return redirect('user_list')
            
        manual_selection = request.POST.get('manual_selection', '').strip()
        users_to_delete = []
        criteria_msg = ""

        if manual_selection:
            users_to_delete = [u.strip() for u in manual_selection.split(',') if u.strip()]
            criteria_msg = f"Manual selection ({len(users_to_delete)} users)"
        else:
            prefix = request.POST.get('prefix', '').strip()
            user_length = request.POST.get('user_length', '').strip()
            
            if not prefix and not user_length:
                messages.error(request, "Please select users manually or provide search criteria.")
                return redirect('user_list')
                
            sql = "SELECT username FROM radcheck WHERE 1=1"
            params = []
            if prefix:
                sql += " AND username LIKE %s"
                params.append(f"{prefix}%")
                criteria_msg += f"Prefix: '{prefix}' "
            if user_length and user_length.isdigit():
                sql += " AND LENGTH(username) = %s"
                params.append(int(user_length))
                criteria_msg += f"Length: {user_length}"
                
            with connection.cursor() as cursor:
                cursor.execute(sql, params)
                users_to_delete = [row[0] for row in cursor.fetchall()]

        if not users_to_delete:
            messages.info(request, "No users found matching the criteria.")
            return redirect('user_list')
            
        count = len(users_to_delete)
        with connection.cursor() as cursor:
            # Batch delete in chunks of 500 to avoid SQL limit issues
            for i in range(0, count, 500):
                chunk = users_to_delete[i:i + 500]
                placeholders = ', '.join(['%s'] * len(chunk))
                cursor.execute(f"DELETE FROM radcheck WHERE username IN ({placeholders})", chunk)
                cursor.execute(f"DELETE FROM radusergroup WHERE username IN ({placeholders})", chunk)
                cursor.execute(f"DELETE FROM approved_users WHERE username IN ({placeholders})", chunk)
            
        # Record activity log
        AdminActivityLog.objects.create(
            admin_user=request.user.username,
            action='Bulk Delete',
            target=f"{count} users",
            details=f"Criteria: {criteria_msg}. Sample users: {', '.join(users_to_delete[:10])}..."
        )
        
        messages.success(request, f"Successfully deleted {count} users.")
            
    return redirect('user_list')


@login_required
def analytics_dashboard(request):
    """
    Traffic Dashboard: Real-time status and historical trends.
    Uses Python-side aggregation for robustness against Timezone db issues.
    """
    # 1. Real-time Active Users
    active_users_count = Radacct.objects.using('default').filter(acctstoptime__isnull=True).count()

    # Timezone Setup (Local Time)
    tz = timezone.get_current_timezone()
    now_local = timezone.now().astimezone(tz)
    
    # Start of Today (Local Midnight)
    start_of_today = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # 2. Today's Total Bandwidth (GB)
    today_qs = Radacct.objects.using('default').filter(acctstarttime__gte=start_of_today)
    
    today_stats = today_qs.aggregate(
        total_in=Coalesce(Sum('acctinputoctets'), 0),
        total_out=Coalesce(Sum('acctoutputoctets'), 0)
    )
    total_bytes_today = (today_stats['total_in'] or 0) + (today_stats['total_out'] or 0)
    bandwidth_gb_today = round(total_bytes_today / (1024**3), 2)

    # 3. Top 10 Users (Today)
    top_users_qs = (
        today_qs
        .values('username')
        .annotate(
            total_usage=Sum(F('acctinputoctets') + F('acctoutputoctets'))
        )
        .order_by('-total_usage')[:10]
    )
    
    top_user_names = []
    top_user_usage = []
    for user in top_users_qs:
        top_user_names.append(user['username'])
        top_user_usage.append(round((user['total_usage'] or 0) / (1024**3), 2))

    # 4. 7 Days History Chart (Active Users & Bandwidth)
    start_of_7d = start_of_today - timedelta(days=6)
    
    # Fetch raw data for Python processing
    history_logs = Radacct.objects.using('default').filter(
        acctstarttime__gte=start_of_7d
    ).values('acctstarttime', 'username', 'acctinputoctets', 'acctoutputoctets')
    
    # Prepare Buckets
    history_map = {}
    current_date = start_of_7d
    date_labels = []
    
    # Initialize map for last 7 days (inclusive of today)
    for _ in range(7):
        d_str = current_date.strftime('%Y-%m-%d')
        history_map[d_str] = {'users': set(), 'bandwidth': 0}
        date_labels.append(d_str)
        current_date += timedelta(days=1)
        
    # Aggregate data
    for log in history_logs:
        # Convert Log Time (UTC/Aware) to Local Date
        if log['acctstarttime']:
            local_dt = log['acctstarttime'].astimezone(tz)
            d_str = local_dt.strftime('%Y-%m-%d')
            
            if d_str in history_map:
                history_map[d_str]['users'].add(log['username'])
                b_in = log['acctinputoctets'] or 0
                b_out = log['acctoutputoctets'] or 0
                history_map[d_str]['bandwidth'] += (b_in + b_out)

    # Convert to Lists for Chart
    daily_users = []
    daily_bandwidth = []
    
    for d_str in date_labels:
        data = history_map[d_str]
        daily_users.append(len(data['users']))
        daily_bandwidth.append(round(data['bandwidth'] / (1024**3), 2))

    # 5. Hourly Usage (Today) - Python Side
    hourly_counts = [0] * 24
    hours_labels = list(range(24))
    
    # Reuse today_qs data roughly? Or better fetch hourly explicitly?
    # Fetch just hours for today
    today_hours = today_qs.values('acctstarttime')
    for h in today_hours:
        if h['acctstarttime']:
            local_dt = h['acctstarttime'].astimezone(tz)
            hourly_counts[local_dt.hour] += 1
    
    context = {
        'active_users_count': active_users_count,
        'bandwidth_gb_today': bandwidth_gb_today,
        # Chart Data
        'dates': json.dumps(date_labels),
        'user_counts': json.dumps(daily_users),
        'bandwidth_data': json.dumps(daily_bandwidth),
        
        # Top Users
        'top_user_names': json.dumps(top_user_names),
        'top_user_usage': json.dumps(top_user_usage),
        
        # Hourly
        'hours': json.dumps(hours_labels),
        'hourly_counts': json.dumps(hourly_counts),
        
        'title': 'Traffic & Analytics Dashboard'
    }

    return render(request, 'hotspot/analytics_dashboard.html', context)
