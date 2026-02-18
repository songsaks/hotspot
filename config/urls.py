from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from hotspot.views import (
    user_list, user_create, user_import, 
    manage_profiles, assign_user_group, 
    delete_profile, remove_user_from_group,
    edit_profile, dashboard, active_sessions, 
    kick_user, delete_user, usage_report, manage_vouchers,
    self_register, registration_requests, approve_user, reject_user,
    member_directory, user_autocomplete, reset_password, toggle_user_status,
    admin_logs, compliance_report, export_compliance_csv,
    bulk_delete_users, analytics_dashboard,
)
from hotspot.views_traffic import traffic_log_report, traffic_log_list
from hotspot.views_search import user_session_search

from django.views.generic import RedirectView

urlpatterns = [
    # Redirect old path to new path
    path('admin/requests/', RedirectView.as_view(pattern_name='registration_requests', permanent=True)),
    
    # Self Registration & Approvals (Priority)
    path('register/', self_register, name='self_register'),
    path('portal/requests/', registration_requests, name='registration_requests'),
    path('portal/requests/approve/<int:pk>/', approve_user, name='approve_user'),
    path('portal/requests/reject/<int:pk>/', reject_user, name='reject_user'),
    path('portal/members/', member_directory, name='member_directory'),
    path('portal/logs/', admin_logs, name='admin_logs'),
    path('portal/compliance/', compliance_report, name='compliance_report'),
    path('portal/compliance/export/', export_compliance_csv, name='export_compliance_csv'),
    path('portal/users/bulk-delete/', bulk_delete_users, name='bulk_delete_users'),
    path('api/user-autocomplete/', user_autocomplete, name='user_autocomplete'),

    path('admin/', admin.site.urls),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='hotspot/login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    path('', dashboard, name='dashboard'),
    path('dashboard/', dashboard, name='dashboard'),
    
    # User Management
    path('users/', user_list, name='user_list'),
    path('users/add/', user_create, name='user_create'),
    path('users/import/', user_import, name='user_import'),
    path('users/delete/<str:username>/', delete_user, name='delete_user'),
    path('users/reset-password/<str:username>/', reset_password, name='reset_password'),
    path('users/toggle-status/<str:username>/', toggle_user_status, name='toggle_user_status'),
    
    # Active Sessions & Reports
    path('sessions/', active_sessions, name='active_sessions'),
    path('sessions/kick/<str:username>/', kick_user, name='kick_user'),
    path('reports/usage/', usage_report, name='usage_report'),
    path('reports/traffic/', traffic_log_report, name='traffic_log_report'),
    path('reports/traffic/list/', traffic_log_list, name='traffic_log_list'),
    path('reports/analytics/', analytics_dashboard, name='analytics_dashboard'),
    path('reports/search/', user_session_search, name='user_session_search'),
    
    # Voucher / Ticket Management
    path('vouchers/', manage_vouchers, name='manage_vouchers'),
    
    # Profile Management
    path('profiles/', manage_profiles, name='manage_profiles'),
    path('profiles/assign/', assign_user_group, name='assign_user_group'),
    path('profiles/edit/<str:groupname>/', edit_profile, name='edit_profile'),
    path('profiles/delete/<str:groupname>/', delete_profile, name='delete_profile'),
    path('profiles/remove-user/<str:username>/', remove_user_from_group, name='remove_user_from_group'),
]