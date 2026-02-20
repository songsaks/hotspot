from django.contrib import admin
from .models import UserRouterAccess

@admin.register(UserRouterAccess)
class UserRouterAccessAdmin(admin.ModelAdmin):
    list_display = ('user', 'router_ip', 'memo', 'created_at')
    list_filter = ('user',)
    search_fields = ('user__username', 'router_ip', 'memo')
# Register your models here.
