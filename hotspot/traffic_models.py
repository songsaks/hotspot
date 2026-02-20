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
        ]

    def __str__(self):
        return f"{self.log_time} - {self.source_ip} -> {self.url}"
