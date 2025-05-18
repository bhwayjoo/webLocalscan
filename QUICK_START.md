# Network Monitor - Quick Start Guide

This guide will help you get started with the Network Monitor application. This Django-based web application allows you to:

1. Discover devices on your local network
2. Scan for open ports on devices
3. Identify services running on these ports
4. Monitor network changes over time

## Prerequisites

- Python 3.9+ installed
- Nmap installed (required for port scanning)
  - Windows: Download and install from [nmap.org](https://nmap.org/download.html)
  - Linux: `sudo apt install nmap` (Debian/Ubuntu) or `sudo yum install nmap` (CentOS/RHEL)
  - macOS: `brew install nmap` (using Homebrew)
- Administrator/root privileges (required for network scanning)

## Setup Instructions

1. Clone the repository or extract the project files
2. Navigate to the project directory
3. Create a virtual environment:
   ```
   python -m venv venv
   ```
4. Activate the virtual environment:
   - Windows: `.\venv\Scripts\activate`
   - Linux/macOS: `source venv/bin/activate`
5. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
6. Apply database migrations:
   ```
   python manage.py migrate
   ```
7. Create a superuser:
   ```
   python manage.py createsuperuser
   ```
8. Run the development server:
   ```
   python manage.py runserver
   ```
9. Access the application at [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

## Running Network Scans

### Using the Web Interface

1. Navigate to the main dashboard
2. Click on "Scan Network" to discover devices
3. Click on a specific device to view details
4. Use "Scan Ports" or "Detect Services" buttons for deeper analysis

### Using the Command Line

You can run network scans directly from the command line:

```
# Discover devices on the network
python manage.py scan_network --network 192.168.1.0/24

# Scan ports on a specific device
python manage.py scan_network --target 192.168.1.100 --ports 1-1024

# Scan UDP ports
python manage.py scan_network --target 192.168.1.100 --ports 1-1024 --protocol udp
```

## Features

### Network Discovery

- Finds all devices on your local network
- Identifies IP addresses, MAC addresses, and hostnames
- Updates device status in real-time

### Port Scanning

- Scans for open TCP and UDP ports
- Flexible port range specification
- Low-impact scanning options

### Service Detection

- Identifies services running on open ports
- Detects service versions when possible
- Flags potentially vulnerable services

### Monitoring and History

- Tracks devices joining and leaving the network
- Records all scan activities
- Provides historical data for analysis

## Troubleshooting

### Permission Issues

If you encounter permission errors during scanning:

- Windows: Run the command prompt or PowerShell as Administrator
- Linux/macOS: Use `sudo` to run the application

### Scan Performance

If scans are too slow:

- Limit the network range (e.g., /24 subnet)
- Specify a smaller port range
- Use the `--discovery-only` flag to skip port scanning

### Missing Devices

If devices aren't showing up:

- Verify the device is connected to the network
- Check that you're scanning the correct network range
- Try disabling any firewalls temporarily

## Security Considerations

- Only use this tool on networks you own or have permission to scan
- Frequent port scanning may trigger security alerts
- Some network admins may consider port scanning as suspicious activity

## Need Help?

If you encounter any issues or have questions, please refer to the project repository or documentation.
