# Network Monitor - Installation and Deployment Guide

This guide provides detailed instructions for deploying the Network Monitor application in a production environment.

## System Requirements

- Python 3.9+
- Nmap 7.80+
- PostgreSQL 12+ (recommended for production)
- 2GB+ RAM
- Modern web browser (Chrome, Firefox, Edge, Safari)
- Linux server (recommended) or Windows Server

## Installation Steps

### 1. Set Up the Environment

#### Linux (Ubuntu/Debian)

```bash
# Install required system packages
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap postgresql postgresql-contrib nginx

# Create a user for the application
sudo useradd -m -s /bin/bash netmonitor
sudo passwd netmonitor

# Switch to the user
sudo su - netmonitor
```

#### Windows Server

- Install Python from [python.org](https://www.python.org/downloads/)
- Install Nmap from [nmap.org](https://nmap.org/download.html)
- Install PostgreSQL from [postgresql.org](https://www.postgresql.org/download/windows/)
- Install IIS or another web server for production deployment

### 2. Create the Database (PostgreSQL)

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE networkmonitor;
CREATE USER netmonitor WITH PASSWORD 'strongpassword';
ALTER ROLE netmonitor SET client_encoding TO 'utf8';
ALTER ROLE netmonitor SET default_transaction_isolation TO 'read committed';
ALTER ROLE netmonitor SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE networkmonitor TO netmonitor;
\q
```

### 3. Set Up the Application

```bash
# Clone the repository or copy the application files
git clone https://github.com/yourusername/network-monitor.git
cd network-monitor

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Gunicorn (Linux production server)
pip install gunicorn
```

### 4. Configure the Application

Create a `.env` file in the project root:

```
DEBUG=False
SECRET_KEY=your-secure-secret-key-here
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,your-server-ip

# Database settings
DB_ENGINE=django.db.backends.postgresql
DB_NAME=networkmonitor
DB_USER=netmonitor
DB_PASSWORD=strongpassword
DB_HOST=localhost
DB_PORT=5432
```

Update `settings.py` to use these environment variables (this should already be configured).

### 5. Initialize the Database

```bash
# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic
```

### 6. Set Up Gunicorn (Linux)

Create a systemd service file at `/etc/systemd/system/networkmonitor.service`:

```
[Unit]
Description=Network Monitor Gunicorn daemon
After=network.target

[Service]
User=netmonitor
Group=www-data
WorkingDirectory=/home/netmonitor/network-monitor
ExecStart=/home/netmonitor/network-monitor/venv/bin/gunicorn --access-logfile - --workers 3 --bind unix:/home/netmonitor/network-monitor/networkmonitor.sock network_monitor.wsgi:application

[Install]
WantedBy=multi-user.target
```

### 7. Configure Nginx (Linux)

Create an Nginx site configuration at `/etc/nginx/sites-available/networkmonitor`:

```
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location = /favicon.ico { access_log off; log_not_found off; }

    location /static/ {
        root /home/netmonitor/network-monitor;
    }

    location /media/ {
        root /home/netmonitor/network-monitor;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/home/netmonitor/network-monitor/networkmonitor.sock;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/networkmonitor /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

### 8. Start the Application

```bash
# Start Gunicorn service
sudo systemctl start networkmonitor
sudo systemctl enable networkmonitor

# Check status
sudo systemctl status networkmonitor
```

### 9. Set Up SSL (Recommended)

Use Let's Encrypt for free SSL certificates:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

## Windows IIS Deployment

For Windows servers using IIS:

1. Install the [URL Rewrite Module](https://www.iis.net/downloads/microsoft/url-rewrite)
2. Install [Web Platform Installer](https://www.microsoft.com/web/downloads/platform.aspx)
3. Install WFastCGI using Web Platform Installer
4. Configure a new IIS site pointing to your application directory
5. Add handler mapping for Python using FastCGI

Detailed IIS configuration is beyond the scope of this guide. Please refer to the Django documentation for Windows deployment.

## Scheduled Tasks

Set up scheduled tasks to run regular network scans:

### Linux (using cron)

```bash
# Edit crontab
crontab -e

# Add scheduled tasks
# Run discovery every hour
0 * * * * /home/netmonitor/network-monitor/venv/bin/python /home/netmonitor/network-monitor/manage.py scan_network --network 192.168.1.0/24 --discovery-only >> /home/netmonitor/network-monitor/logs/discovery.log 2>&1

# Run full scan at 2 AM daily
0 2 * * * /home/netmonitor/network-monitor/venv/bin/python /home/netmonitor/network-monitor/manage.py scan_network --network 192.168.1.0/24 >> /home/netmonitor/network-monitor/logs/full_scan.log 2>&1
```

### Windows (using Task Scheduler)

1. Open Task Scheduler
2. Create a new task
3. Set the trigger (e.g., daily at 2 AM)
4. Set the action to run a program:
   - Program: `C:\path\to\venv\Scripts\python.exe`
   - Arguments: `C:\path\to\network-monitor\manage.py scan_network --network 192.168.1.0/24`

## Maintenance

### Backups

Set up regular database backups:

```bash
# PostgreSQL backup script
pg_dump -U netmonitor networkmonitor > /path/to/backup/networkmonitor_$(date +%Y%m%d).sql
```

### Updates

To update the application:

1. Activate the virtual environment
2. Pull the latest code (if using git)
3. Install any new dependencies
4. Apply database migrations
5. Restart the service

```bash
source venv/bin/activate
git pull
pip install -r requirements.txt
python manage.py migrate
sudo systemctl restart networkmonitor
```

## Monitoring and Troubleshooting

### Logs

Check application logs:

- Gunicorn logs: `journalctl -u networkmonitor`
- Nginx logs: `/var/log/nginx/error.log` and `/var/log/nginx/access.log`
- Application logs: Configure Django logging in settings.py

### Common Issues

1. **Permission errors during scanning**: Ensure the application has sufficient privileges to perform network scans. On Linux, you may need to run with sudo or use capabilities.

2. **Database connection issues**: Verify PostgreSQL is running and the credentials are correct.

3. **Web server errors**: Check Nginx/IIS logs for configuration issues.

## Security Considerations

1. Set up a firewall to restrict access to the server
2. Use strong passwords for all accounts
3. Keep the server and dependencies updated
4. Use HTTPS (SSL/TLS) for all connections
5. Limit access to the admin interface

## Performance Tuning

For larger networks:

1. Increase the number of Gunicorn workers
2. Configure database connection pooling
3. Add caching using Redis or Memcached
4. Implement task queues for scan operations using Celery
