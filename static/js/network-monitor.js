// Network Monitor JavaScript functions

// Function to format timestamp
function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString();
}

// Function to validate IP address
function validateIPAddress(ip) {
  const regex =
    /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return regex.test(ip);
}

// Function to validate CIDR notation
function validateCIDR(cidr) {
  const parts = cidr.split("/");
  if (parts.length !== 2) return false;

  const ip = parts[0];
  const prefix = parseInt(parts[1], 10);

  if (!validateIPAddress(ip)) return false;
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  return true;
}

// Function to display an alert
function showAlert(message, type = "info") {
  const alertDiv = document.createElement("div");
  alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
  alertDiv.role = "alert";

  alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

  const container = document.querySelector(".main-content");
  container.insertBefore(alertDiv, container.firstChild);

  // Auto-dismiss after 5 seconds
  setTimeout(() => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(alertDiv);
    bsAlert.close();
  }, 5000);
}

// Function to refresh device data
function refreshDeviceData(deviceId = null) {
  const url = deviceId ? `/api/devices/${deviceId}/` : "/api/devices/";

  fetch(url)
    .then((response) => response.json())
    .then((data) => {
      // Update UI with new data
      if (window.updateDeviceUI) {
        window.updateDeviceUI(data);
      }
    })
    .catch((error) => {
      console.error("Error refreshing device data:", error);
    });
}

// Set up periodic refresh
function setupPeriodicRefresh(interval = 30000) {
  setInterval(() => {
    refreshDeviceData();
  }, interval);
}

// Function to start a network scan
function scanNetwork(networkRange, callback) {
  if (!validateCIDR(networkRange)) {
    showAlert(
      "Invalid network range. Please use CIDR notation (e.g., 192.168.1.0/24)",
      "danger"
    );
    return;
  }

  fetch("/api/devices/discover/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ network_range: networkRange }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (callback && typeof callback === "function") {
        callback(data);
      }
    })
    .catch((error) => {
      console.error("Error scanning network:", error);
      showAlert("Failed to scan network. Please try again.", "danger");
    });
}

// Function to scan ports on a device
function scanPorts(ip, portRange = "1-1024", protocol = "tcp", callback) {
  if (!validateIPAddress(ip)) {
    showAlert("Invalid IP address", "danger");
    return;
  }

  fetch("/api/ports/scan/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      target: ip,
      port_range: portRange,
      protocol: protocol,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      if (callback && typeof callback === "function") {
        callback(data);
      }
    })
    .catch((error) => {
      console.error("Error scanning ports:", error);
      showAlert("Failed to scan ports. Please try again.", "danger");
    });
}

// Function to detect services on a device
function detectServices(ip, ports = null, callback) {
  if (!validateIPAddress(ip)) {
    showAlert("Invalid IP address", "danger");
    return;
  }

  const requestData = { target: ip };
  if (ports) {
    requestData.ports = ports;
  }

  fetch("/api/ports/detect_services/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(requestData),
  })
    .then((response) => response.json())
    .then((data) => {
      if (callback && typeof callback === "function") {
        callback(data);
      }
    })
    .catch((error) => {
      console.error("Error detecting services:", error);
      showAlert("Failed to detect services. Please try again.", "danger");
    });
}

// Initialize tooltips and popovers when the document is ready
document.addEventListener("DOMContentLoaded", function () {
  // Initialize tooltips
  const tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Initialize popovers
  const popoverTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="popover"]')
  );
  popoverTriggerList.map(function (popoverTriggerEl) {
    return new bootstrap.Popover(popoverTriggerEl);
  });
});
