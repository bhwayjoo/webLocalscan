# Network Monitor API Documentation

This document provides detailed information about the REST API endpoints available in the Network Monitor application.

## Base URL

All API endpoints are relative to the base URL: `http://localhost:8000/api/`

## Authentication

The API uses token-based authentication for secure access. You need to include an authentication token in the header of your requests.

To obtain a token, you can use Django's admin interface or implement a custom token generation endpoint.

Include the token in your requests:

```
Authorization: Token your-auth-token-here
```

## API Endpoints

### Devices

#### List all devices

```
GET /devices/
```

**Response:**

```json
[
  {
    "id": 1,
    "ip_address": "192.168.1.1",
    "mac_address": "00:11:22:33:44:55",
    "hostname": "router.local",
    "vendor": "Cisco Systems",
    "status": "active",
    "first_seen": "2025-05-18T14:30:00Z",
    "last_seen": "2025-05-18T15:00:00Z",
    "ports": [
      {
        "id": 1,
        "port_number": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "nginx",
        "version": "1.18.0",
        "status": "open",
        "last_scanned": "2025-05-18T15:00:00Z"
      }
    ]
  }
]
```

#### Get a specific device

```
GET /devices/{id}/
```

**Response:**

```json
{
  "id": 1,
  "ip_address": "192.168.1.1",
  "mac_address": "00:11:22:33:44:55",
  "hostname": "router.local",
  "vendor": "Cisco Systems",
  "status": "active",
  "first_seen": "2025-05-18T14:30:00Z",
  "last_seen": "2025-05-18T15:00:00Z",
  "ports": [
    {
      "id": 1,
      "port_number": 80,
      "protocol": "tcp",
      "service": "http",
      "product": "nginx",
      "version": "1.18.0",
      "status": "open",
      "last_scanned": "2025-05-18T15:00:00Z"
    }
  ]
}
```

#### Discover devices on the network

```
POST /devices/discover/
```

**Request Body:**

```json
{
  "network_range": "192.168.1.0/24"
}
```

**Response:**

```json
{
  "success": true,
  "devices": [
    {
      "ip_address": "192.168.1.1",
      "mac_address": "00:11:22:33:44:55",
      "hostname": "router.local"
    },
    {
      "ip_address": "192.168.1.100",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "hostname": "desktop.local"
    }
  ]
}
```

### Ports

#### List all ports

```
GET /ports/
```

**Response:**

```json
[
  {
    "id": 1,
    "port_number": 80,
    "protocol": "tcp",
    "service": "http",
    "product": "nginx",
    "version": "1.18.0",
    "status": "open",
    "last_scanned": "2025-05-18T15:00:00Z"
  }
]
```

#### Scan ports on a device

```
POST /ports/scan/
```

**Request Body:**

```json
{
  "target": "192.168.1.100",
  "port_range": "1-1024", // optional, defaults to "1-1024"
  "protocol": "tcp" // optional, defaults to "tcp"
}
```

**Response:**

```json
{
  "success": true,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "state": "open"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "state": "open"
    }
  ]
}
```

#### Detect services on a device

```
POST /ports/detect_services/
```

**Request Body:**

```json
{
  "target": "192.168.1.100",
  "ports": "22,80,443" // optional, if not provided, all open ports will be scanned
}
```

**Response:**

```json
{
  "success": true,
  "services": {
    "22": {
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "product": "OpenSSH",
      "version": "8.4p1",
      "state": "open"
    },
    "80": {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "product": "nginx",
      "version": "1.18.0",
      "state": "open"
    }
  }
}
```

### Scan History

#### List scan history

```
GET /scan-history/
```

**Response:**

```json
[
  {
    "id": 1,
    "start_time": "2025-05-18T14:30:00Z",
    "end_time": "2025-05-18T14:35:00Z",
    "scan_type": "discovery",
    "target_range": "192.168.1.0/24",
    "devices_found": 10,
    "status": "completed"
  },
  {
    "id": 2,
    "start_time": "2025-05-18T15:00:00Z",
    "end_time": "2025-05-18T15:10:00Z",
    "scan_type": "port_scan",
    "target_range": "192.168.1.100",
    "devices_found": 1,
    "status": "completed"
  }
]
```

#### Get specific scan history

```
GET /scan-history/{id}/
```

**Response:**

```json
{
  "id": 1,
  "start_time": "2025-05-18T14:30:00Z",
  "end_time": "2025-05-18T14:35:00Z",
  "scan_type": "discovery",
  "target_range": "192.168.1.0/24",
  "devices_found": 10,
  "status": "completed"
}
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK`: The request was successful
- `201 Created`: A resource was successfully created
- `400 Bad Request`: The request was invalid or cannot be served
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: The request is forbidden
- `404 Not Found`: The requested resource could not be found
- `500 Internal Server Error`: An error occurred on the server

Error responses include a message:

```json
{
  "success": false,
  "error": "Error message description"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse. You may receive a `429 Too Many Requests` status if you exceed the rate limits.

## Webhooks

The Network Monitor API supports webhooks for real-time notifications about network events. You can configure webhooks in the admin interface.

Events that trigger webhooks:

- New device discovered
- Device status change
- Open port detected
- Service identification

## API Versioning

The current API version is v1. The version is implied in the API endpoints.
Future versions will be explicitly versioned (e.g., `/api/v2/devices/`).
