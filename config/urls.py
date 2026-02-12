from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from hotspot.views import (
    user_list, user_create, user_import, 
    manage_profiles, assign_user_group, 
    delete_profile, remove_user_from_group,
    edit_profile, dashboard
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='hotspot/login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    path('', dashboard, name='dashboard'), # Default home to dashboard
    path('dashboard/', dashboard, name='dashboard'),
    path('users/', user_list, name='user_list'),
    path('users/add/', user_create, name='user_create'),
    path('users/import/', user_import, name='user_import'),
    path('profiles/', manage_profiles, name='manage_profiles'),
    path('profiles/assign/', assign_user_group, name='assign_user_group'),
    path('profiles/edit/<str:groupname>/', edit_profile, name='edit_profile'),
    path('profiles/delete/<str:groupname>/', delete_profile, name='delete_profile'),
    path('profiles/remove-user/<str:username>/', remove_user_from_group, name='remove_user_from_group'),
]