// Application-specific JavaScript for Network Monitor

document.addEventListener("DOMContentLoaded", function () {
  // Get current page
  const currentPath = window.location.pathname;

  // Initialize specific page functionality
  if (currentPath === "/" || currentPath === "/dashboard/") {
    initDashboard();
  } else if (currentPath.includes("/devices/")) {
    if (currentPath === "/devices/") {
      initDeviceList();
    } else {
      initDeviceDetail();
    }
  } else if (currentPath === "/scan-history/") {
    initScanHistory();
  }

  // Setup general functionality
  setupGeneralFunctionality();
});

// Dashboard initialization
function initDashboard() {
  console.log("Dashboard initialized");

  // Load dashboard data
  loadDashboardData();

  // Setup refresh interval (every 30 seconds)
  setInterval(loadDashboardData, 30000);
}

// Load dashboard data via API
function loadDashboardData() {
  fetch("/api/devices/")
    .then((response) => response.json())
    .then((data) => {
      updateDeviceCount(data.length);
      updateDevicesList(data);
      updatePortsCount(data);
    })
    .catch((error) => console.error("Error loading dashboard data:", error));

  // Load recent scans
  fetch("/api/scan-history/")
    .then((response) => response.json())
    .then((data) => {
      updateRecentScans(data.slice(0, 5));
    })
    .catch((error) => console.error("Error loading scan history:", error));
}

// Update device count in dashboard
function updateDeviceCount(count) {
  const activeCount = document.getElementById("active-devices-count");
  if (activeCount) {
    activeCount.textContent = count;
  }
}

// Update devices list in dashboard
function updateDevicesList(devices) {
  const devicesList = document.getElementById("devices-table-body");
  if (!devicesList) return;

  if (devices.length === 0) {
    devicesList.innerHTML =
      '<tr><td colspan="5" class="text-center">No devices found</td></tr>';
    return;
  }

  devicesList.innerHTML = "";
  devices.forEach((device) => {
    const row = document.createElement("tr");

    // Create IP address cell
    const ipCell = document.createElement("td");
    ipCell.textContent = device.ip_address;
    row.appendChild(ipCell);

    // Create hostname cell
    const hostnameCell = document.createElement("td");
    hostnameCell.textContent = device.hostname || "Unknown";
    row.appendChild(hostnameCell);

    // Create MAC address cell
    const macCell = document.createElement("td");
    macCell.textContent = device.mac_address || "N/A";
    row.appendChild(macCell);

    // Create status cell
    const statusCell = document.createElement("td");
    const statusBadge = document.createElement("span");
    statusBadge.className = `status-badge ${
      device.status === "active" ? "bg-success" : "bg-secondary"
    }`;
    statusBadge.textContent = device.status;
    statusCell.appendChild(statusBadge);
    row.appendChild(statusCell);

    // Create actions cell
    const actionsCell = document.createElement("td");

    // Detail button
    const detailBtn = document.createElement("a");
    detailBtn.href = `/devices/${device.id}/`;
    detailBtn.className = "btn btn-sm btn-outline-primary me-1";
    detailBtn.innerHTML = '<i class="fas fa-eye"></i>';
    actionsCell.appendChild(detailBtn);

    // Scan button
    const scanBtn = document.createElement("button");
    scanBtn.className = "btn btn-sm btn-outline-info scan-ports-btn";
    scanBtn.dataset.ip = device.ip_address;
    scanBtn.innerHTML = '<i class="fas fa-search"></i>';
    scanBtn.addEventListener("click", function () {
      scanPorts(device.ip_address);
    });
    actionsCell.appendChild(scanBtn);

    row.appendChild(actionsCell);

    devicesList.appendChild(row);
  });
}

// Update ports count in dashboard
function updatePortsCount(devices) {
  const portsCount = document.getElementById("open-ports-count");
  if (!portsCount) return;

  let total = 0;
  devices.forEach((device) => {
    total += device.ports ? device.ports.length : 0;
  });

  portsCount.textContent = total;
}

// Update recent scans in dashboard
function updateRecentScans(scans) {
  const scansList = document.getElementById("recent-scans-list");
  if (!scansList) return;

  if (scans.length === 0) {
    scansList.innerHTML =
      '<li class="list-group-item text-center">No recent scans</li>';
    return;
  }

  scansList.innerHTML = "";
  scans.forEach((scan) => {
    const item = document.createElement("li");
    item.className = "list-group-item";

    const scanDate = new Date(scan.start_time);

    item.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1">${scan.scan_type
                      .replace("_", " ")
                      .replace(/\b\w/g, (l) => l.toUpperCase())} Scan</h6>
                    <small>${scan.target_range}</small>
                </div>
                <span class="status-badge ${
                  scan.status === "completed"
                    ? "bg-success"
                    : scan.status === "failed"
                    ? "bg-danger"
                    : "bg-warning"
                }">
                    ${scan.status.replace(/\b\w/g, (l) => l.toUpperCase())}
                </span>
            </div>
            <small class="text-muted">${scanDate.toLocaleString()}</small>
        `;

    scansList.appendChild(item);
  });
}

// Device list page initialization
function initDeviceList() {
  console.log("Device list page initialized");

  // Attach event listeners to scan buttons
  document.querySelectorAll(".scan-device-btn").forEach((button) => {
    button.addEventListener("click", function () {
      const ip = this.dataset.ip;
      initDeviceScan(ip);
    });
  });
}

// Device detail page initialization
function initDeviceDetail() {
  console.log("Device detail page initialized");

  // Attach event listeners
  const scanPortsBtn = document.getElementById("scan-ports-btn");
  if (scanPortsBtn) {
    scanPortsBtn.addEventListener("click", function () {
      const ip = this.dataset.ip;
      initPortScan(ip);
    });
  }

  const scanServicesBtn = document.getElementById("scan-services-btn");
  if (scanServicesBtn) {
    scanServicesBtn.addEventListener("click", function () {
      const ip = this.dataset.ip;
      initServiceScan(ip);
    });
  }
}

// Scan history page initialization
function initScanHistory() {
  console.log("Scan history page initialized");

  // Nothing specific to initialize
}

// Setup functionality common to all pages
function setupGeneralFunctionality() {
  // Handle network scan form submission
  const scanNetworkForm = document.getElementById("network-scan-form");
  if (scanNetworkForm) {
    const startScanBtn = document.getElementById("start-network-scan-btn");
    if (startScanBtn) {
      startScanBtn.addEventListener("click", function () {
        submitNetworkScan();
      });
    }
  }
}

// Submit network scan
function submitNetworkScan() {
  const networkRange = document.getElementById("network-range").value;

  // Display scanning indicator
  document.getElementById("network-scan-form").classList.add("d-none");
  document.getElementById("scan-progress").classList.remove("d-none");
  document.getElementById("start-network-scan-btn").disabled = true;

  // Call API
  fetch("/api/devices/discover/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": getCookie("csrftoken"),
    },
    body: JSON.stringify({ network_range: networkRange }),
  })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById(
        "scan-status-text"
      ).textContent = `Scan completed! Found ${data.devices.length} devices.`;

      // Reload the page after a delay
      setTimeout(function () {
        window.location.reload();
      }, 2000);
    })
    .catch((error) => {
      console.error("Error scanning network:", error);
      document.getElementById("scan-status-text").textContent =
        "Scan failed. Please try again.";

      // Re-enable the form
      setTimeout(function () {
        document.getElementById("network-scan-form").classList.remove("d-none");
        document.getElementById("scan-progress").classList.add("d-none");
        document.getElementById("start-network-scan-btn").disabled = false;
      }, 2000);
    });
}

// Initialize device scan modal
function initDeviceScan(ip) {
  // Set the IP in the form
  document.getElementById("device-ip").value = ip;

  // Update modal title
  document.getElementById(
    "scanDeviceModalLabel"
  ).textContent = `Scan Device: ${ip}`;

  // Show the modal
  const modal = new bootstrap.Modal(document.getElementById("scanDeviceModal"));
  modal.show();
}

// Initialize port scan modal
function initPortScan(ip) {
  // Show the modal
  const modal = new bootstrap.Modal(document.getElementById("scanPortsModal"));
  modal.show();
}

// Initialize service scan modal
function initServiceScan(ip) {
  // Show the modal
  const modal = new bootstrap.Modal(
    document.getElementById("detectServicesModal")
  );
  modal.show();
}

// Scan ports on a device
function scanPorts(ip) {
  if (!confirm(`Scan ports on ${ip}?`)) {
    return;
  }

  fetch("/api/ports/scan/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": getCookie("csrftoken"),
    },
    body: JSON.stringify({ target: ip }),
  })
    .then((response) => response.json())
    .then((data) => {
      alert(`Scan completed. Found ${data.ports.length} open ports.`);
      window.location.reload();
    })
    .catch((error) => {
      console.error("Error scanning ports:", error);
      alert("Port scan failed. Please try again.");
    });
}

// Get CSRF token from cookies
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === name + "=") {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
