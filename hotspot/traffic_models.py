from django.db import models

class TrafficLog(models.Model):
    log_time = models.DateTimeField()
    nas_ip = models.CharField(max_length=45, blank=True, null=True)
    source_ip = models.CharField(max_length=45)  # Supprot IPv6
    destination_ip = models.CharField(max_length=45)
    url = models.CharField(max_length=500, blank=True, null=True)  # Domain or Full Log Message
    method = models.TextField(blank=True, null=True) # Full Log Details
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'traffic_log'
        managed = True
        ordering = ['-log_time']
        indexes = [
            models.Index(fields=['-log_time'], name='idx_traffic_logtime'),
            models.Index(fields=['nas_ip', '-log_time'], name='idx_traffic_nas_time'),
            models.Index(fields=['source_ip'], name='idx_traffic_srcip'),
            models.Index(fields=['destination_ip'], name='idx_traffic_dstip'),
        ]

    def __str__(self):
        return f"{self.log_time} - {self.source_ip} -> {self.url}"

class DailyWebsiteStats(models.Model):
    date = models.DateField()
    nas_ip = models.CharField(max_length=45, blank=True, null=True)
    domain = models.CharField(max_length=255)
    visit_count = models.BigIntegerField(default=0)
    unique_users = models.IntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'daily_website_stats'
        managed = True
        unique_together = ('date', 'nas_ip', 'domain')
        indexes = [
            models.Index(fields=['date', 'nas_ip'], name='idx_stats_date_nas'),
            models.Index(fields=['domain'], name='idx_stats_domain'),
        ]

    def __str__(self):
        return f"{self.date} - {self.domain} ({self.visit_count})"
