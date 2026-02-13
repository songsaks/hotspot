from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import connection
from django.contrib.auth.decorators import login_required
import pandas as pd
import random
import string
from .models import Radcheck, PendingUser, ApprovedUser
from .forms import HotspotUserForm, UserImportForm

@login_required
def dashboard(request):
    return render(request, 'hotspot/dashboard.html')

# ... existing code ...

@login_required
def registration_requests(request):
    pending_users = PendingUser.objects.all().order_by('-created_at')
    
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
            messages.success(request, f"User '{pending.username}' approved and assigned to '{groupname}'.")
        else:
            messages.error(request, "Please select a profile.")
    return redirect('registration_requests')

@login_required
def reject_user(request, pk):
    pending = get_object_or_404(PendingUser, pk=pk)
    pending.delete()
    messages.warning(request, f"Registration request for '{pending.username}' has been rejected.")
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
            
        # Check if username already exists in either table
        if Radcheck.objects.filter(username=username).exists() or PendingUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
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
def user_list(request):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT rc.id, rc.username, rc.value as password, rug.groupname, au.id as is_self_reg
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            LEFT JOIN approved_users au ON rc.username = au.username
            ORDER BY rc.id DESC LIMIT 100
        """)
        users = dictfetchall(cursor)
        cursor.execute("SELECT DISTINCT groupname FROM radgroupreply")
        profiles = dictfetchall(cursor)

    return render(request, 'hotspot/user_list.html', {
        'users': users,
        'profiles': profiles
    })

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
    
    return render(request, 'hotspot/usage_report.html', {'usage_data': usage_data})

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
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM radgroupreply WHERE groupname = %s", [groupname])
        cursor.execute("DELETE FROM radusergroup WHERE groupname = %s", [groupname])
    messages.success(request, f"Profile '{groupname}' deleted.")
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