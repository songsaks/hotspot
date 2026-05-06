from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('hotspot', '0013_dailywebsitestats_unique_users'),
    ]

    operations = [
        migrations.AddField(
            model_name='pendinguser',
            name='router_ip',
            field=models.CharField(blank=True, help_text='IP of the router where request originated', max_length=50, null=True),
        ),
    ]
