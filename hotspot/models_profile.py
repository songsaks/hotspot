from django.db import models
from django.contrib.auth.models import User

class UserProfileGroup(models.Model):
    groupname = models.CharField(max_length=64, primary_key=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_global = models.BooleanField(default=False, help_text="If True, all branches can see/use this profile (but only Superadmin can edit)")

    class Meta:
        db_table = 'user_profile_group'
        managed = True
    
    def __str__(self):
        return self.groupname
