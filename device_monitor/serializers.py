from rest_framework import serializers
from .models import Device, Port, ScanHistory

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = ('id', 'port_number', 'protocol', 'service', 'product', 'version', 'status', 'last_scanned')

class DeviceSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True, read_only=True)
    
    class Meta:
        model = Device
        fields = ('id', 'ip_address', 'mac_address', 'hostname', 'vendor', 'status', 'first_seen', 'last_seen', 'ports')

class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = ('id', 'start_time', 'end_time', 'scan_type', 'target_range', 'devices_found', 'status')
