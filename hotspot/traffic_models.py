from django.db import models

class TrafficLog(models.Model):
    log_time = models.DateTimeField()
    source_ip = models.CharField(max_length=45)  # Supprot IPv6
    destination_ip = models.CharField(max_length=45)
    url = models.CharField(max_length=255)  # Domain or URL
    method = models.CharField(max_length=10, blank=True, null=True) # GET, POST etc (Optional)
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'traffic_log'
        managed = True  # Set to True so Django can create the table
        ordering = ['-log_time']

    def __str__(self):
        return f"{self.log_time} - {self.source_ip} -> {self.url}"
