from django.contrib import admin
from .models import Device, Port, ScanHistory

class PortInline(admin.TabularInline):
    model = Port
    extra = 0

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'mac_address', 'hostname', 'vendor', 'status', 'last_seen')
    list_filter = ('status',)
    search_fields = ('ip_address', 'mac_address', 'hostname', 'vendor')
    inlines = [PortInline]

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('device', 'port_number', 'protocol', 'service', 'status', 'last_scanned')
    list_filter = ('status', 'protocol')
    search_fields = ('device__ip_address', 'port_number', 'service')

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'target_range', 'devices_found', 'status', 'start_time', 'end_time')
    list_filter = ('scan_type', 'status')
    search_fields = ('target_range',)
