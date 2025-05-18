from django.shortcuts import render
from django.http import JsonResponse
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from .models import Device, Port, ScanHistory
from .serializers import DeviceSerializer, PortSerializer, ScanHistorySerializer
from .utils import NetworkScanner

# Web views
def dashboard(request):
    """Main dashboard view"""
    context = {
        'devices_count': Device.objects.count(),
        'active_devices': Device.objects.filter(status='active').count(),
        'recent_scans': ScanHistory.objects.all()[:5]
    }
    return render(request, 'device_monitor/dashboard.html', context)

def device_list(request):
    """View for displaying all devices"""
    context = {
        'devices': Device.objects.all()
    }
    return render(request, 'device_monitor/device_list.html', context)

def device_detail(request, device_id):
    """View for displaying device details"""
    device = Device.objects.get(id=device_id)
    context = {
        'device': device,
        'ports': device.ports.all()
    }
    return render(request, 'device_monitor/device_detail.html', context)

def scan_history(request):
    """View for displaying scan history"""
    context = {
        'scans': ScanHistory.objects.all()
    }
    return render(request, 'device_monitor/scan_history.html', context)

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
