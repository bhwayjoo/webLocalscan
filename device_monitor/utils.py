import nmap
import socket
import ipaddress
from scapy.all import ARP, Ether, srp
from django.utils import timezone
from .models import Device, Port, ScanHistory

class NetworkScanner:
    """
    Utilities for network scanning operations including device discovery,
    port scanning, and service detection.
    """
    
    @staticmethod
    def discover_devices(network_range):
        """
        Discover devices in the specified network range using ARP requests.
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            list: List of dictionaries containing discovered device information
        """
        # Create scan history record
        scan = ScanHistory.objects.create(
            scan_type='discovery',
            target_range=network_range,
            status='in_progress'
        )
        
        discovered_devices = []
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process responses
            for sent, received in result:
                device_info = {
                    'ip_address': received.psrc,
                    'mac_address': received.hwsrc,
                    'hostname': None
                }
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                    device_info['hostname'] = hostname
                except (socket.herror, socket.gaierror):
                    pass
                
                # Save device to database or update if it exists
                device, created = Device.objects.update_or_create(
                    ip_address=device_info['ip_address'],
                    defaults={
                        'mac_address': device_info['mac_address'],
                        'hostname': device_info['hostname'],
                        'last_seen': timezone.now()
                    }
                )
                
                discovered_devices.append(device_info)
            
            # Update scan history
            scan.devices_found = len(discovered_devices)
            scan.status = 'completed'
            scan.end_time = timezone.now()
            scan.save()
            
            return discovered_devices
            
        except Exception as e:
            # Update scan history with error
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
            raise e
    
    @staticmethod
    def scan_ports(target, port_range='1-1024', protocol='tcp'):
        """
        Scan for open ports on a target device.
        
        Args:
            target (str): IP address to scan
            port_range (str): Range of ports to scan, e.g., "1-1024" or specific ports "22,80,443"
            protocol (str): Protocol to scan, either 'tcp' or 'udp'
            
        Returns:
            list: List of dictionaries containing port information
        """
        # Create scan history record
        scan = ScanHistory.objects.create(
            scan_type='port_scan',
            target_range=target,
            status='in_progress'
        )
        
        try:
            # Get or create the device
            device, _ = Device.objects.get_or_create(
                ip_address=target,
                defaults={'last_seen': timezone.now()}
            )
            
            # Initialize scanner
            scanner = nmap.PortScanner()
            
            # Perform scan
            arguments = f'-p{port_range}'
            if protocol == 'udp':
                arguments += ' -sU'
            
            scanner.scan(hosts=target, arguments=arguments)
            
            open_ports = []
            
            # Process results
            if target in scanner.all_hosts():
                for proto in scanner[target].all_protocols():
                    for port in scanner[target][proto].keys():
                        port_info = scanner[target][proto][port]
                        
                        if port_info['state'] == 'open':
                            # Save port to database
                            Port.objects.update_or_create(
                                device=device,
                                port_number=port,
                                protocol=proto,
                                defaults={
                                    'status': port_info['state'],
                                    'service': port_info.get('name', ''),
                                    'last_scanned': timezone.now()
                                }
                            )
                            
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', ''),
                                'state': port_info['state']
                            })
            
            # Update scan history
            scan.devices_found = 1
            scan.status = 'completed'
            scan.end_time = timezone.now()
            scan.save()
            
            return open_ports
            
        except Exception as e:
            # Update scan history with error
            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
            raise e
    
    @staticmethod
    def detect_services(target, ports=None):
        """
        Perform service detection on open ports.
        
        Args:
            target (str): IP address to scan
            ports (str, optional): Specific ports to scan, e.g., "22,80,443"
            
        Returns:
            dict: Dictionary with detailed service information
        """
        # Create scan history record
        scan = ScanHistory.objects.create(
            scan_type='service_scan',
            target_range=target,
            status='in_progress'
        )
        
        try:
            # Get the device
            device = Device.objects.get(ip_address=target)
            
            # Initialize scanner
            scanner = nmap.PortScanner()
            
            # Build arguments
            arguments = '-sV'
            if ports:
                arguments += f' -p{ports}'
            
            # Perform scan
            scanner.scan(hosts=target, arguments=arguments)
            
            services = {}
            
            # Process results
            if target in scanner.all_hosts():
                for proto in scanner[target].all_protocols():
                    for port in scanner[target][proto].keys():
                        port_info = scanner[target][proto][port]
                        
                        if port_info['state'] == 'open':
                            # Update port in database with service info
                            Port.objects.update_or_create(
                                device=device,
                                port_number=port,
                                protocol=proto,
                                defaults={
                                    'status': port_info['state'],
                                    'service': port_info.get('name', ''),
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'last_scanned': timezone.now()
                                }
                            )
                            
                            services[port] = {
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', ''),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'state': port_info['state']
                            }
            
            # Update scan history
            scan.devices_found = 1
            scan.status = 'completed'
            scan.end_time = timezone.now()
            scan.save()
            
            return services
            
        except Exception as e:
            # Update scan history with error            scan.status = 'failed'
            scan.end_time = timezone.now()
            scan.save()
            raise e
            
    @staticmethod
    def monitor_network(network_range):
        """
        Monitor network for new devices and status changes.
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            dict: Dictionary containing monitoring results
        """
        from .models import Alert, IPWhitelist
        
        # Get currently known devices
        known_devices = {device.ip_address: device for device in Device.objects.all()}
        
        # Get whitelisted IP addresses
        whitelisted_ips = set(ip.ip_address for ip in IPWhitelist.objects.filter(is_active=True))
        
        # Discover current devices on the network
        discovered_devices = NetworkScanner.discover_devices(network_range)
        
        # Check for new devices and create alerts
        results = {
            'total_devices': len(discovered_devices),
            'new_devices': [],
            'unauthorized_devices': [],
            'alerts_generated': 0
        }
        
        # Process discovered devices
        for device_info in discovered_devices:
            ip_address = device_info['ip_address']
            
            # If this is first time we're seeing this device
            if ip_address not in known_devices:
                try:
                    # Get the newly created device from the database
                    device = Device.objects.get(ip_address=ip_address)
                    
                    # Create an alert for the new device
                    alert = Alert.objects.create(
                        device=device,
                        alert_type='new_device',
                        severity='warning',
                        message=f"New device detected on network: {device.hostname or 'Unknown'} ({device.ip_address})",
                        details={
                            'ip_address': device.ip_address,
                            'mac_address': device.mac_address,
                            'hostname': device.hostname,
                            'first_seen': device.first_seen.isoformat()
                        }
                    )
                    
                    results['new_devices'].append({
                        'ip_address': device.ip_address,
                        'hostname': device.hostname,
                        'mac_address': device.mac_address,
                        'alert_id': alert.id
                    })
                    
                    results['alerts_generated'] += 1
                except Device.DoesNotExist:
                    # This shouldn't happen if discover_devices is working correctly
                    pass
                except Exception as e:
                    # Log the error but continue
                    pass
                
            # Check if the device is not in the whitelist
            if ip_address not in whitelisted_ips:
                try:
                    device = Device.objects.get(ip_address=ip_address)
                    
                    # Create an alert for unauthorized device
                    alert = Alert.objects.create(
                        device=device,
                        alert_type='security',
                        severity='critical',
                        message=f"Unauthorized device detected: {device.hostname or 'Unknown'} ({device.ip_address})",
                        details={
                            'ip_address': device.ip_address,
                            'mac_address': device.mac_address,
                            'hostname': device.hostname,
                            'whitelisted': False
                        }
                    )
                    
                    results['unauthorized_devices'].append({
                        'ip_address': device.ip_address,
                        'hostname': device.hostname,
                        'mac_address': device.mac_address,
                        'alert_id': alert.id
                    })
                    
                    results['alerts_generated'] += 1
                except Exception as e:
                    # Log the error but continue
                    pass
        
        return results


