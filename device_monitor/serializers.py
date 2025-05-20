from rest_framework import serializers
from .models import Device, Port, ScanHistory, Alert, IPWhitelist

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = '__all__'

class DeviceSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True, read_only=True)
    is_whitelisted = serializers.SerializerMethodField()
    
    class Meta:
        model = Device
        fields = '__all__'
        depth = 1
    
    def get_is_whitelisted(self, obj):
        """Check if the device's IP is in the whitelist"""
        return IPWhitelist.objects.filter(ip_address=obj.ip_address, is_active=True).exists()

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = '__all__'

class ScanHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanHistory
        fields = '__all__'

class IPWhitelistSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPWhitelist
        fields = '__all__'
