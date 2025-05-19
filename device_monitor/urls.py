from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Setup the DRF router
router = DefaultRouter()
router.register(r'devices', views.DeviceViewSet)
router.register(r'ports', views.PortViewSet)
router.register(r'scan-history', views.ScanHistoryViewSet)
router.register(r'alerts', views.AlertViewSet, basename='alert')
router.register(r'ip-whitelist', views.IPWhitelistViewSet, basename='ip-whitelist')

# URL patterns for both web and API views
urlpatterns = [
    # Web views
    path('', views.dashboard, name='dashboard'),
    path('devices/', views.device_list, name='device_list'),
    path('devices/<int:device_id>/', views.device_detail, name='device_detail'),
    path('scan-history/', views.scan_history, name='scan_history'),
    path('alerts/', views.device_alerts, name='device_alerts'),
    path('ip-whitelist/', views.ip_whitelist, name='ip_whitelist'),
    
    # API endpoints
    path('api/', include(router.urls)),
]
