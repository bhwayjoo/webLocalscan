from django.db import models
from django.utils import timezone

class Device(models.Model):
    """Model representing a network device."""
    ip_address = models.GenericIPAddressField(unique=True)
    mac_address = models.CharField(max_length=17, blank=True, null=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=50, default='active')
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"{self.hostname or 'Unknown'} ({self.ip_address})"
    
    class Meta:
        ordering = ['ip_address']

class Port(models.Model):
    """Model representing an open port on a device."""
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10, choices=[('tcp', 'TCP'), ('udp', 'UDP')], default='tcp')
    service = models.CharField(max_length=255, blank=True, null=True)
    product = models.CharField(max_length=255, blank=True, null=True)
    version = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=50, default='open')
    last_scanned = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"{self.device.ip_address}:{self.port_number}/{self.protocol}"
    
    class Meta:
        unique_together = ['device', 'port_number', 'protocol']
        ordering = ['port_number']

class ScanHistory(models.Model):
    """Model for storing scan history."""
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    scan_type = models.CharField(max_length=50, choices=[
        ('discovery', 'Network Discovery'),
        ('port_scan', 'Port Scan'),
        ('service_scan', 'Service Detection')
    ])
    target_range = models.CharField(max_length=255)
    devices_found = models.IntegerField(default=0)
    status = models.CharField(max_length=50, default='in_progress')
    
    def __str__(self):
        return f"{self.scan_type} scan of {self.target_range} at {self.start_time}"
    
    class Meta:
        ordering = ['-start_time']
        verbose_name_plural = 'Scan Histories'


class Alert(models.Model):
    """Model for storing network alerts."""
    ALERT_TYPES = [
        ('new_device', 'New Device Detected'),
        ('status_change', 'Device Status Change'),
        ('port_change', 'Open Port Change'),
        ('security', 'Security Alert')
    ]
    
    SEVERITY_LEVELS = [
        ('info', 'Information'),
        ('warning', 'Warning'),
        ('critical', 'Critical')
    ]
    
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='info')
    message = models.TextField()
    details = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.get_alert_type_display()} - {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']
