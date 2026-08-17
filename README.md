Here is a complete, detailed, and comprehensive `README.md` for **Blackbox Sentinel**, written professionally without icons or emojis.

***

# Blackbox Sentinel: Commercial Cyber-Physical Defense Appliance

Blackbox Sentinel is a turnkey commercial security software appliance and air-gapped command center built on top of the `libblackbox.so` security engine and the `libxinfer.so` AI runtime. Designed for military installations, critical infrastructure, smart factories, and high-assurance data centers, Blackbox Sentinel provides active, sub-millisecond threat mitigation, a real-time web command dashboard, enterprise RBAC authentication, TPM 2.0 node locking, and automated compliance forensic reporting.

---

## Architecture Stack

Blackbox Sentinel represents Layer 3 (The Commercial Application Layer) in the product ecosystem:

```text
===================================================================================
 LAYER 3: BLACKBOX SENTINEL (Commercial Product Application)
 - Air-Gapped Web Command Center Dashboard
 - TLS 1.3 / JWT Authenticated C++ REST API & WebSocket Server
 - TPM 2.0 Hardware Licensing & Anti-Piracy Module
 - CMMC / ISO 27001 PDF & CSV Forensic Audit Exporter
===================================================================================
                                         |
                                         v (Links against libblackbox.so)
===================================================================================
 LAYER 2: LIBBLACKBOX.SO (Core Security & Active Mitigation Engine)
 - eBPF / XDP Kernel IP Packet Dropper
 - Multi-Modal Cyber-Physical Threat Correlator
 - Lock-Free Ring Buffers & Encrypted Audit Database
===================================================================================
                                         |
                                         v (Links against libxinfer.so)
===================================================================================
 LAYER 1: LIBXINFER.SO (Universal C++20 AI Runtime)
 - Hardware Abstraction (NVIDIA TensorRT, Intel OpenVINO, Rockchip RKNN)
 - Zero-Copy DMA Memory & Hardware-Accelerated Pre/Post Processing
===================================================================================
```

---

## Core Commercial Features

- Air-Gapped Web Command Center: Served locally by an embedded C++ HTTP server over HTTPS (port 8443) with WebSockets streaming live incident data in under 1 millisecond.
- Role-Based Access Control (RBAC): Enterprise user authentication enforcing strict segregation between Administrators, Security Analysts, and Compliance Auditors.
- Active eBPF Kernel Management: Interactive dashboard displaying active eBPF blocked IP addresses with 1-click manual unblock overrides and whitelist rules.
- Hardware Telemetry & Health Monitoring: Real-time visual tracking of CPU temperature, RAM usage, network bandwidth, and NPU/GPU utilization meters.
- TPM 2.0 Node Locking: Anti-piracy licensing engine that binds software execution to the appliance's physical motherboard TPM 2.0 chip and hardware serial numbers.
- Automated Compliance Exporter: Generates formal forensic PDF, CSV, and JSON audit reports for CMMC, ISO 27001, STIG, and NIST 800-53 compliance standards.

---

## Repository File Structure

```text
blackbox-sentinel/
├── CMakeLists.txt                    # Main product build configuration
├── LICENSE                           # Commercial Enterprise License
├── README.md                         # Commercial Product Documentation
│
├── configs/                          # Default Product Settings & Policies
│   ├── sentinel_config.json          # System settings, TLS, RBAC, & API ports
│   └── default_rules.json            # Pre-installed threat detection rules
│
├── deploy/                           # OS Packaging & Deployment Automation
│   ├── install_appliance.sh          # One-command bare-metal installer script
│   ├── sentinel.service              # Linux systemd service unit file
│   └── yocto/                        # Immutable Linux image builder scripts
│
├── src/                              # Commercial Product C++ Application Source
│   ├── main.cpp                      # Sentinel Daemon entry point
│   │
│   ├── api/                          # REST API & WebSocket Controllers
│   │   ├── auth_manager.hpp          # User authentication & JWT token header
│   │   ├── auth_manager.cpp          # RBAC enforcement & password hashing
│   │   ├── rest_controller.hpp       # REST API endpoints header
│   │   ├── rest_controller.cpp       # REST request router & JSON handlers
│   │   ├── ws_streamer.hpp           # Real-time WebSocket streamer header
│   │   └── ws_streamer.cpp           # Live incident WebSocket feed logic
│   │
│   ├── exporter/                     # Compliance & Forensic Reporting
│   │   ├── report_generator.hpp      # PDF/CSV report exporter header
│   │   └── report_generator.cpp      # CMMC / ISO27001 compliance report builder
│   │
│   └── hardware/                     # Hardware Telemetry & Security
│       ├── hw_monitor.hpp            # Hardware sensor monitor header
│       ├── hw_monitor.cpp            # CPU/GPU/NPU temperature & load reader
│       ├── tpm_license.hpp           # TPM 2.0 node locking header
│       └── tpm_license.cpp           # Hardware fingerprint & key validator
│
└── web/                              # Production Air-Gapped Web UI
    ├── index.html                    # Main command center HTML layout
    ├── assets/                       # UI CSS & JS libraries
    │   ├── chart.min.js              # Real-time telemetry chart library
    │   └── tailwind.min.css          # Responsive UI CSS framework
    └── js/
        ├── blocked_ips.js            # Live eBPF blocked IP table manager
        ├── dashboard.js              # Real-time WebSocket visualizer
        └── rules_builder.js          # Interactive threat rule editor
```

---

## System Requirements & Prerequisites

### Operating System
- Ubuntu 22.04 LTS / 24.04 LTS Server, Debian 12, or Yocto Immutable Linux
- Kernel version 5.15+ (Required for eBPF XDP driver support)

### Core Shared Libraries
Blackbox Sentinel requires both shared libraries compiled and installed in `/usr/local/lib`:
1. `libxinfer.so` (Universal AI Engine)
2. `libblackbox.so` (Core Security Engine)

### Development Dependencies
- C++20 Compiler: GCC 10+ or Clang 12+
- CMake 3.20+
- OpenSSL 3.0+ (For TLS 1.3 and JWT encryption)
- SQLite3 (`libsqlite3-dev`)

---

## Installation and Build Instructions

### 1. Automated Turnkey Appliance Installation

On a fresh bare-metal server or edge board running Ubuntu, execute the automated installer script:

```bash
chmod +x deploy/install_appliance.sh
sudo ./deploy/install_appliance.sh
```

### 2. Manual CMake Build Steps

If building manually from source:

```bash
# 1. Ensure libxinfer.so and libblackbox.so are installed
sudo ldconfig

# 2. Create build directory
mkdir build && cd build

# 3. Configure CMake
cmake ..

# 4. Compile Sentinel Daemon
make -j$(nproc)

# 5. Install Sentinel Service
sudo make install
```

---

## Appliance Configuration (`configs/sentinel_config.json`)

```json
{
  "appliance": {
    "node_id": "sentinel-alpha-01",
    "facility_name": "DataCenter-Zone-A",
    "http_port": 8443,
    "websocket_port": 8444,
    "enable_tls": true,
    "tls_cert_path": "/etc/sentinel/certs/server.crt",
    "tls_key_path": "/etc/sentinel/certs/server.key"
  },
  "authentication": {
    "jwt_secret": "SUPERSIG_SECRET_KEY_CHANGE_IN_PRODUCTION",
    "session_timeout_minutes": 60,
    "max_failed_logins": 5
  },
  "hardware_security": {
    "enforce_tpm_lock": false,
    "allowed_serial_number": "HW-NODE-9982341A"
  },
  "blackbox_engine": {
    "network_interface": "eth0",
    "xinfer_target": "TensorRT",
    "threat_model_path": "/var/lib/sentinel/models/threat_detector.engine",
    "auto_mitigation_enabled": true
  }
}
```

---

## REST API Specification

All REST API endpoints are served over HTTPS and require a valid Bearer JWT Token passed in the `Authorization` header.

### Authentication
- `POST /api/v1/auth/login`
  - Request Body: `{"username": "admin", "password": "<password>"}`
  - Response: `{"token": "<jwt_token>", "role": "Administrator"}`

### Threat Management
- `GET /api/v1/threats`
  - Returns recent threat incidents, anomaly scores, and actions taken.
- `GET /api/v1/blocked-ips`
  - Returns all currently active eBPF kernel blocked IP addresses.
- `POST /api/v1/unblock-ip`
  - Request Body: `{"ip_address": "192.168.1.250"}`
  - Removes IP from eBPF drop map.

### Hardware & System Metrics
- `GET /api/v1/system-health`
  - Returns CPU, GPU, NPU temperatures, RAM usage, and packet throughput.

### Compliance Export
- `POST /api/v1/export-report`
  - Request Body: `{"format": "pdf", "standard": "CMMC_LEVEL_2", "time_range": "24h"}`
  - Downloads an encrypted forensic audit report.

---

## Running as a System Service

Blackbox Sentinel runs as an unkillable Linux daemon managed by `systemd`.

To start and enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel
```

To view live status and appliance logs:

```bash
sudo systemctl status sentinel
sudo journalctl -u sentinel -f
```

---

## Appliance Deployment Hardware Tiers

Blackbox Sentinel is commercially deployed in two hardware configurations:

1. **Tactical ARM / Jetson Node (Tier A):** Designed for drones, military vehicles, and remote field sites. Runs on Rockchip RK3588 or NVIDIA Jetson Orin Nano on low-power battery (< 25W).
2. **Enterprise 1U Rackmount Server (Tier B):** Designed for data centers, nuclear power plants, and smart factories. Runs on Intel Core Ultra / Xeon or AMD EPYC with dual 10GbE SFP+ eBPF hardware-accelerated NICs.

---

## License

Blackbox Sentinel is commercial proprietary software. See `LICENSE` for commercial licensing terms, OEM distribution agreements, and support terms.