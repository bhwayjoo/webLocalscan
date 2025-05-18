# Network Monitor

A comprehensive Django web application for monitoring devices connected to a local network, scanning for open ports, and identifying services.

![Network Monitor Dashboard](https://via.placeholder.com/800x450.png?text=Network+Monitor+Dashboard)

## 🌟 Features

- **Network Discovery**: Automatically detect all devices on your local network
- **Port Scanning**: Identify open ports on detected devices
- **Service Detection**: Recognize services running on open ports
- **Real-time Monitoring**: Track devices joining and leaving the network
- **Visualization**: User-friendly dashboard with device and port statistics
- **Scan History**: Keep track of all scanning activities
- **REST API**: Full-featured API for integration with other tools
- **Responsive UI**: Modern, mobile-friendly interface

## 🚀 Quick Start

1. Clone the repository or extract the project files
2. Create and activate a virtual environment:
   ```
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Apply database migrations:
   ```
   python manage.py migrate
   ```
5. Create an admin user:
   ```
   python manage.py createsuperuser
   ```
6. Run the development server:
   ```
   python manage.py runserver
   ```
7. Access the application at [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

For more detailed instructions, see [QUICK_START.md](QUICK_START.md)

## 📋 Requirements

- Python 3.9+
- Django 5.0+
- Nmap (for port scanning)
- Other dependencies listed in requirements.txt

## 🛠️ Installation and Deployment

For production deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md)

## 🔍 Usage

### Web Interface

The web interface provides a user-friendly way to:

- View a dashboard of network devices
- Scan your network for new devices
- Check port and service information
- Review scan history

### Command Line

You can also use the built-in management commands:

```bash
# Discover devices on the network
python manage.py scan_network --network 192.168.1.0/24

# Scan ports on a specific device
python manage.py scan_network --target 192.168.1.100 --ports 1-1024
```

### REST API

The application provides a full REST API:

```bash
# Get all devices
curl http://localhost:8000/api/devices/

# Scan for new devices
curl -X POST http://localhost:8000/api/devices/discover/ \
     -H "Content-Type: application/json" \
     -d '{"network_range": "192.168.1.0/24"}'

# Scan ports on a device
curl -X POST http://localhost:8000/api/ports/scan/ \
     -H "Content-Type: application/json" \
     -d '{"target": "192.168.1.100", "port_range": "1-1024"}'
```

## 🏗️ Architecture

The application is built with Django and consists of several main components:

- **Network Scanner Module**: Uses nmap and scapy for device discovery and port scanning
- **Device Tracking Database**: Stores information about devices and their ports
- **Web Interface**: User-friendly dashboard and device management
- **REST API**: Provides programmatic access to all functionality
- **Background Tasks**: Regular scanning and monitoring tasks

## 🛡️ Security Notes

- This application should only be used on networks you own or have permission to scan
- Port scanning can be detected by security tools and may trigger alerts
- Running port scans too frequently can cause network performance issues
- Some service detection techniques may cause services to log connection attempts

## 📚 Documentation

- [Quick Start Guide](QUICK_START.md)
- [Deployment Guide](DEPLOYMENT.md)
- [API Documentation](API.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Django](https://www.djangoproject.com/) - The web framework used
- [Nmap](https://nmap.org/) - Network scanning library
- [Scapy](https://scapy.net/) - Packet manipulation library
- [Bootstrap](https://getbootstrap.com/) - Frontend framework
