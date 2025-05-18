from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Setup the DRF router
router = DefaultRouter()
router.register(r'devices', views.DeviceViewSet)
router.register(r'ports', views.PortViewSet)
router.register(r'scan-history', views.ScanHistoryViewSet)

# URL patterns for both web and API views
urlpatterns = [
    # Web views
    path('', views.dashboard, name='dashboard'),
    path('devices/', views.device_list, name='device_list'),
    path('devices/<int:device_id>/', views.device_detail, name='device_detail'),
    path('scan-history/', views.scan_history, name='scan_history'),
    
    # API endpoints
    path('api/', include(router.urls)),
]
