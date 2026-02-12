"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from hotspot.views import (
    user_list, user_create, user_import, 
    manage_profiles, assign_user_group, 
    delete_profile, remove_user_from_group,
    edit_profile
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('users/', user_list, name='user_list'),
    path('users/add/', user_create, name='user_create'),
    path('users/import/', user_import, name='user_import'),
    path('profiles/', manage_profiles, name='manage_profiles'),
    path('profiles/assign/', assign_user_group, name='assign_user_group'),
    path('profiles/edit/<str:groupname>/', edit_profile, name='edit_profile'),
    path('profiles/delete/<str:groupname>/', delete_profile, name='delete_profile'),
    path('profiles/remove-user/<str:username>/', remove_user_from_group, name='remove_user_from_group'),
]