from django.shortcuts import render
from django.http import JsonResponse
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from .models import Device, Port, ScanHistory, Alert, IPWhitelist
from .serializers import DeviceSerializer, PortSerializer, ScanHistorySerializer, IPWhitelistSerializer
from .utils import NetworkScanner

# Web views
def dashboard(request):
    """Main dashboard view"""
    # Get whitelisted IPs
    whitelisted_ips = set(ip.ip_address for ip in IPWhitelist.objects.filter(is_active=True))
    
    # Get devices not in whitelist
    all_devices = Device.objects.all()
    unauthorized_devices = [device for device in all_devices if device.ip_address not in whitelisted_ips]
    
    context = {
        'devices_count': all_devices.count(),
        'active_devices': Device.objects.filter(status='active').count(),
        'recent_scans': ScanHistory.objects.all()[:5],
        'recent_alerts': Alert.objects.all().order_by('-timestamp')[:5],
        'unauthorized_count': len(unauthorized_devices),
        'recent_unauthorized': unauthorized_devices[:5],
        'whitelisted_count': IPWhitelist.objects.filter(is_active=True).count(),
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/dashboard.html', context)

def device_list(request):
    """View for displaying all devices"""
    context = {
        'devices': Device.objects.all(),
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/device_list.html', context)

def device_detail(request, device_id):
    """View for displaying device details"""
    device = Device.objects.get(id=device_id)
    context = {
        'device': device,
        'ports': device.ports.all(),
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/device_detail.html', context)

def scan_history(request):
    """View for displaying scan history"""
    context = {
        'scans': ScanHistory.objects.all(),
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/scan_history.html', context)

def device_alerts(request):
    """View for displaying device alerts"""
    context = {
        'alerts': Alert.objects.all().order_by('-timestamp')[:100],  # Get the 100 most recent alerts
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/device_alerts.html', context)

def ip_whitelist(request):
    """View for managing IP whitelist"""
    context = {
        'whitelist': IPWhitelist.objects.all().order_by('ip_address'),
        'unread_count': Alert.objects.filter(is_read=False).count()
    }
    return render(request, 'device_monitor/ip_whitelist.html', context)

# API viewsets
class DeviceViewSet(viewsets.ModelViewSet):
    """API endpoint for devices"""
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    
    @action(detail=False, methods=['post'])
    def discover(self, request):
        """Discover devices on the network"""
        network_range = request.data.get('network_range', '192.168.1.0/24')
        
        try:
            discovered_devices = NetworkScanner.discover_devices(network_range)
            return Response({'success': True, 'devices': discovered_devices})
        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def monitor(self, request):
        """Monitor network for new devices and create alerts"""
        network_range = request.data.get('network_range', '192.168.1.0/24')
        
        try:
            results = NetworkScanner.monitor_network(network_range)
            return Response({
                'success': True, 
                'devices_found': results['total_devices'],
                'new_devices': results['new_devices'],
                'alerts_generated': results['alerts_generated']
            })
        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PortViewSet(viewsets.ModelViewSet):
    """API endpoint for ports"""
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    
    @action(detail=False, methods=['post'])
    def scan(self, request):
        """Scan ports on a device"""
        target = request.data.get('target')
        port_range = request.data.get('port_range', '1-1024')
        protocol = request.data.get('protocol', 'tcp')
        
        if not target:
            return Response(
                {'success': False, 'error': 'Target IP is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            ports = NetworkScanner.scan_ports(target, port_range, protocol)
            return Response({'success': True, 'ports': ports})
        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def detect_services(self, request):
        """Detect services running on ports"""
        target = request.data.get('target')
        ports = request.data.get('ports')
        
        if not target:
            return Response(
                {'success': False, 'error': 'Target IP is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            services = NetworkScanner.detect_services(target, ports)
            return Response({'success': True, 'services': services})
        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ScanHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for scan history"""
    queryset = ScanHistory.objects.all()
    serializer_class = ScanHistorySerializer

class AlertViewSet(viewsets.ModelViewSet):
    """API endpoint for alerts"""
    queryset = Alert.objects.all().order_by('-timestamp')
    
    @action(detail=True, methods=['post'])
    def mark_as_read(self, request, pk=None):
        """Mark an alert as read"""
        alert = self.get_object()
        alert.is_read = True
        alert.save()
        return Response({'status': 'success'})
    
    @action(detail=False, methods=['post'])
    def mark_all_as_read(self, request):
        """Mark all alerts as read"""
        Alert.objects.filter(is_read=False).update(is_read=True)
        return Response({'status': 'success'})
    
    @action(detail=False, methods=['get'])
    def unread(self, request):
        """Get unread alerts"""
        unread_alerts = Alert.objects.filter(is_read=False).order_by('-timestamp')
        data = [
            {
                'id': alert.id,
                'message': alert.message,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'timestamp': alert.timestamp,
                'device': {
                    'id': alert.device.id,
                    'ip_address': alert.device.ip_address,
                    'hostname': alert.device.hostname
                } if alert.device else None
            }
            for alert in unread_alerts
        ]
        return Response(data)
        
class IPWhitelistViewSet(viewsets.ModelViewSet):
    """API endpoint for IP whitelist management"""
    queryset = IPWhitelist.objects.all()
    serializer_class = IPWhitelistSerializer
    
    def create(self, request):
        """Create a new IP whitelist entry"""
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        """Update an IP whitelist entry"""
        try:
            return super().update(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    def partial_update(self, request, *args, **kwargs):
        """Partially update an IP whitelist entry"""
        try:
            return super().partial_update(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
