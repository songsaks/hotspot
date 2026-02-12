from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import connection
import pandas as pd
from .models import Radcheck
from .forms import HotspotUserForm, UserImportForm

def dictfetchall(cursor):
    "Return all rows from a cursor as a dict"
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

def user_list(request):
    # ดึงข้อมูลจากฐานข้อมูลบน VPS
    users = Radcheck.objects.all().order_by('-id')[:100] # Show last 100
    return render(request, 'hotspot/user_list.html', {'users': users})

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
                
                msg = f'Successfully imported {count} users'
                if selected_profile:
                    msg += f' and assigned to profile "{selected_profile}"'
                messages.success(request, msg + '.')
                return redirect('user_list')
            except Exception as e:
                messages.error(request, f'Error processing file: {str(e)}')
    else:
        form = UserImportForm(profile_choices=profiles)
    
    return render(request, 'hotspot/user_import.html', {'form': form})

def manage_profiles(request):
    with connection.cursor() as cursor:
        if request.method == 'POST' and 'create_profile' in request.POST:
            group_name = request.POST.get('group_name')
            dl_speed = request.POST.get('download_speed') # e.g. 2M
            ul_speed = request.POST.get('upload_speed')   # e.g. 1M
            timeout_hours = request.POST.get('session_timeout') # Hours
            
            rate_limit = f"{ul_speed}/{dl_speed}"
            
            try:
                timeout_seconds = int(timeout_hours) * 3600
                # Insert Rate Limit
                cursor.execute(
                    "INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    [group_name, 'Mikrotik-Rate-Limit', ':=', rate_limit]
                )
                # Insert Session Timeout
                cursor.execute(
                    "INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    [group_name, 'Session-Timeout', ':=', str(timeout_seconds)]
                )
                messages.success(request, f"Profile '{group_name}' created successfully!")
            except Exception as e:
                messages.error(request, f"Error creating profile: {str(e)}")
            return redirect('manage_profiles')

        # Get all profiles with their values
        cursor.execute("SELECT groupname, attribute, value FROM radgroupreply")
        reply_rows = dictfetchall(cursor)
        
        profiles_dict = {}
        for row in reply_rows:
            gn = row['groupname']
            attr = row['attribute']
            val = row['value']
            if gn not in profiles_dict:
                profiles_dict[gn] = {'groupname': gn, 'speed': 'N/A', 'timeout': 'N/A'}
            
            if attr == 'Mikrotik-Rate-Limit':
                profiles_dict[gn]['speed'] = val
            elif attr == 'Session-Timeout':
                try:
                    profiles_dict[gn]['timeout'] = int(val) // 3600
                except:
                    profiles_dict[gn]['timeout'] = val
        
        profiles = list(profiles_dict.values())
        
        # Get users in each group
        cursor.execute("SELECT groupname, username FROM radusergroup")
        user_group_rows = dictfetchall(cursor)
        
        group_users = {}
        for row in user_group_rows:
            gn = row['groupname']
            un = row['username']
            if gn not in group_users:
                group_users[gn] = []
            group_users[gn].append(un)
            
        for p in profiles:
            p['user_list'] = group_users.get(p['groupname'], [])
        
        # Get all users for assignment dropdown
        cursor.execute("SELECT DISTINCT username FROM radcheck")
        users = dictfetchall(cursor)

    return render(request, 'hotspot/profile_manager.html', {
        'profiles': profiles,
        'users': users
    })

def edit_profile(request, groupname):
    with connection.cursor() as cursor:
        if request.method == 'POST':
            dl_speed = request.POST.get('download_speed')
            ul_speed = request.POST.get('upload_speed')
            timeout_hours = request.POST.get('session_timeout')
            rate_limit = f"{ul_speed}/{dl_speed}"
            timeout_seconds = int(timeout_hours) * 3600
            
            try:
                # Update Mikrotik-Rate-Limit
                cursor.execute(
                    "UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = 'Mikrotik-Rate-Limit'",
                    [rate_limit, groupname]
                )
                # Update Session-Timeout
                cursor.execute(
                    "UPDATE radgroupreply SET value = %s WHERE groupname = %s AND attribute = 'Session-Timeout'",
                    [str(timeout_seconds), groupname]
                )
                messages.success(request, f"Profile '{groupname}' updated successfully!")
            except Exception as e:
                messages.error(request, f"Error updating profile: {str(e)}")
            return redirect('manage_profiles')

        # Fetch current values for editing
        cursor.execute("SELECT attribute, value FROM radgroupreply WHERE groupname = %s", [groupname])
        rows = dictfetchall(cursor)
        
        data = {'groupname': groupname, 'dl': '', 'ul': '', 'timeout': ''}
        for row in rows:
            if row['attribute'] == 'Mikrotik-Rate-Limit':
                if '/' in row['value']:
                    data['ul'], data['dl'] = row['value'].split('/')
                else:
                    data['dl'] = row['value']
            elif row['attribute'] == 'Session-Timeout':
                try:
                    data['timeout'] = int(row['value']) // 3600
                except:
                    data['timeout'] = row['value']
    
    return render(request, 'hotspot/profile_edit.html', {'data': data})

def delete_profile(request, groupname):
    with connection.cursor() as cursor:
        # Delete from radgroupreply
        cursor.execute("DELETE FROM radgroupreply WHERE groupname = %s", [groupname])
        # Also remove users from this group
        cursor.execute("DELETE FROM radusergroup WHERE groupname = %s", [groupname])
    messages.success(request, f"Profile '{groupname}' and its assignments have been deleted.")
    return redirect('manage_profiles')

def remove_user_from_group(request, username):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM radusergroup WHERE username = %s", [username])
    messages.success(request, f"User '{username}' has been removed from the profile group.")
    return redirect('manage_profiles')

def assign_user_group(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        groupname = request.POST.get('groupname')
        
        with connection.cursor() as cursor:
            # Check if assignment exists
            cursor.execute("SELECT username FROM radusergroup WHERE username = %s", [username])
            exists = cursor.fetchone()
            
            if exists:
                cursor.execute(
                    "UPDATE radusergroup SET groupname = %s WHERE username = %s",
                    [groupname, username]
                )
            else:
                cursor.execute(
                    "INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)",
                    [username, groupname, 1]
                )
        
        messages.success(request, f"User '{username}' assigned to group '{groupname}'")
    return redirect('manage_profiles')