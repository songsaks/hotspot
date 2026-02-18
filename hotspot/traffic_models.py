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
        managed = True  # Set to True so Django can create the table
        ordering = ['-log_time']

    def __str__(self):
        return f"{self.log_time} - {self.source_ip} -> {self.url}"
