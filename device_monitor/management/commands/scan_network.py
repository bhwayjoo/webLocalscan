from django.core.management.base import BaseCommand
from django.utils import timezone
from device_monitor.utils import NetworkScanner
from device_monitor.models import Alert
import argparse
import ipaddress
import time


class Command(BaseCommand):
    help = 'Run network discovery and port scanning'

    def add_arguments(self, parser):
        parser.add_argument(
            '--network',
            type=str,
            default='192.168.1.0/24',
            help='Network range to scan in CIDR notation (e.g., 192.168.1.0/24)'
        )
        parser.add_argument(
            '--ports',
            type=str,
            default='1-1024',
            help='Port range to scan (e.g., 1-1024 or 22,80,443)'
        )
        parser.add_argument(
            '--protocol',
            type=str,
            choices=['tcp', 'udp'],
            default='tcp',
            help='Protocol to scan (tcp or udp)'
        )
        parser.add_argument(
            '--discovery-only',
            action='store_true',
            help='Run only discovery scan without port scanning'
        )
        parser.add_argument(
            '--target',
            type=str,
            help='Specific IP address to scan'
        )
        parser.add_argument(
            '--monitor',
            action='store_true',
            help='Monitor for new devices and generate alerts'
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=300,  # 5 minutes
            help='Interval between scans when monitoring (in seconds)'
        )
        parser.add_argument(
            '--continuous',
            action='store_true',
            help='Run scan or monitoring continuously'
        )

    def handle(self, *args, **options):
        network_range = options['network']
        port_range = options['ports']
        protocol = options['protocol']
        discovery_only = options['discovery_only']
        target = options['target']
        monitor = options['monitor']
        interval = options['interval']
        continuous = options['continuous']

        # Validate network range
        try:
            ipaddress.ip_network(network_range)
        except ValueError:
            self.stderr.write(self.style.ERROR(f'Invalid network range: {network_range}'))
            return
            
        # Handle monitoring mode
        if monitor:
            self._run_monitoring(network_range, interval, continuous)
            return

        # Run network discovery
        if not target:
            self.stdout.write(f'Starting network discovery on {network_range}...')
            try:
                devices = NetworkScanner.discover_devices(network_range)
                self.stdout.write(self.style.SUCCESS(f'Discovered {len(devices)} devices on the network'))
                
                for device in devices:
                    self.stdout.write(f"  - {device['ip_address']} ({device['mac_address'] or 'Unknown MAC'}) {device['hostname'] or ''}")
                
                # If discovery only, we're done
                if discovery_only:
                    return
                
                # Otherwise, scan ports on each device
                for device in devices:
                    self.scan_ports(device['ip_address'], port_range, protocol)
            
            except Exception as e:
                self.stderr.write(self.style.ERROR(f'Error during network discovery: {str(e)}'))
        else:
            # Scan a specific target
            self.scan_ports(target, port_range, protocol)
    
    def scan_ports(self, target, port_range, protocol):
        """Scan ports on the specified target"""
        self.stdout.write(f'Scanning {protocol.upper()} ports {port_range} on {target}...')
        try:
            open_ports = NetworkScanner.scan_ports(target, port_range, protocol)
            
            if open_ports:
                self.stdout.write(self.style.SUCCESS(f'Found {len(open_ports)} open ports on {target}:'))
                for port_info in open_ports:
                    service = port_info.get('service', 'unknown')
                    self.stdout.write(f"  - {port_info['port']}/{port_info['protocol']}: {service}")
                
                # Detect services
                self.stdout.write(f'Detecting services on {target}...')
                ports_str = ','.join(str(p['port']) for p in open_ports)
                try:
                    services = NetworkScanner.detect_services(target, ports_str)
                    self.stdout.write(self.style.SUCCESS(f'Service detection completed on {target}'))
                except Exception as e:
                    self.stderr.write(self.style.ERROR(f'Error during service detection: {str(e)}'))
            else:
                self.stdout.write(f'No open ports found on {target}')
        
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Error during port scanning: {str(e)}'))
    
    def _run_monitoring(self, network_range, interval, continuous):
        """Run network monitoring to detect new devices"""
        import time
        
        self.stdout.write(self.style.SUCCESS(f'Starting network monitoring for {network_range}'))
        
        try:
            # Run once or continuously based on the flag
            if continuous:
                self.stdout.write(f'Running continuously with interval of {interval} seconds')
                while True:
                    self._do_monitor_scan(network_range)
                    time.sleep(interval)
            else:
                self._do_monitor_scan(network_range)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Network monitoring stopped by user'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
    
    def _do_monitor_scan(self, network_range):
        """Perform a single monitoring scan"""
        self.stdout.write(f'Scanning network {network_range} for new devices...')
        results = NetworkScanner.monitor_network(network_range)
        
        if results['alerts_generated'] > 0:
            self.stdout.write(
                self.style.WARNING(
                    f'Found {results["alerts_generated"]} new devices on the network!'
                )
            )
            
            for device in results['new_devices']:
                self.stdout.write(
                    self.style.WARNING(
                        f'New device: {device["hostname"] or "Unknown"} ({device["ip_address"]})'
                    )
                )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f'Scan complete. Found {results["total_devices"]} devices. No new devices detected.'
                )
            )
