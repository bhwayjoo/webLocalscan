import time
from django.core.management.base import BaseCommand
from django.conf import settings
from device_monitor.utils import NetworkScanner
from device_monitor.models import Alert

class Command(BaseCommand):
    help = 'Continuously monitor the network for new devices and generate alerts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--network',
            type=str,
            default='192.168.1.0/24',
            help='Network range to monitor in CIDR notation'
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=300,  # 5 minutes
            help='Interval between scans in seconds'
        )
        parser.add_argument(
            '--continuous',
            action='store_true',
            help='Run continuously instead of one time'
        )

    def handle(self, *args, **options):
        network_range = options['network']
        interval = options['interval']
        continuous = options['continuous']
        
        self.stdout.write(self.style.SUCCESS(f'Starting network monitoring for {network_range}'))
        
        try:
            # Run once or continuously based on the flag
            if continuous:
                self.stdout.write(f'Running continuously with interval of {interval} seconds')
                while True:
                    self._monitor_network(network_range)
                    time.sleep(interval)
            else:
                self._monitor_network(network_range)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Network monitoring stopped by user'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
    
    def _monitor_network(self, network_range):
        self.stdout.write(f'Scanning network {network_range}...')
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