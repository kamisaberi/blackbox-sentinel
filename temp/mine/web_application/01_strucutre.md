Building an **interactive web command center** for **Blackbox Sentinel** is a natural and necessary step. 

For enterprise and defense clients, **the web dashboard is the product**. CISOs, plant managers, and security analysts rarely log into an SSH terminal—they judge the value of a \$25,000 appliance by the responsiveness, control, and clarity of its web interface.

---

### Key Requirements for an Air-Gapped Security UI

Because Blackbox Sentinel is designed for **air-gapped and sovereign networks**, the web application must adhere to two strict rules:
1. **Zero External CDN Dependencies:** It cannot fetch fonts, CSS, or scripts from external URLs (like Google Fonts, CDNJS, or unpkg). All CSS, JavaScript, and icons must be packaged and served locally by the C++ appliance daemon.
2. **Microscopic & Fast:** The frontend should be an ultra-responsive Single Page Application (SPA) served directly by the Sentinel C++ embedded HTTP server on port 8443 without requiring external heavy web frameworks like Node.js or Apache.

---

### 6 Essential Feature Modules for the Interactive Web App

#### 1. Appliance Engine Control (Start / Stop / Restart)
* **What it does:** Allows operators to start, stop, or pause the active defense engine with one click from the browser.
* **UI Element:** A persistent status toggle button: `[RUNNING - STOP ENGINE]` or `[STOPPED - START ENGINE]` with real-time status badges (Green for Active, Amber for Paused, Red for Offline).

#### 2. Live Threat & Incident Console (WebSockets)
* **What it does:** Displays incoming security incidents in real-time as they are processed by `libblackbox.so` and `libxinfer.so`.
* **UI Element:** A high-speed scrolling terminal/table displaying timestamp, event type (Network/Log/Vision), source IP, AI anomaly score (0.00 to 1.00), and mitigation action executed. Color-coded by severity:
  * `CRITICAL` (Red) — eBPF Kernel Blocked
  * `HIGH` (Amber) — Alert / Logged
  * `INFO` (Blue) — Normal traffic

#### 3. Interactive eBPF Kernel Firewall Table
* **What it does:** Displays all IP addresses currently dropped in the Linux kernel eBPF map.
* **UI Element:** An interactive table showing IP, timestamp of block, trigger reason, and an instant **[1-Click Unblock]** button that removes the IP from the kernel drop table in real-time. Also includes a manual input field: `[Enter IP to Block] [Apply Kernel Drop]`.

#### 4. Built-in Attack Simulation Panel (The Demo / Training Center)
* **What it does:** Lets operators or evaluators test the appliance right from the web page without touching a terminal.
* **UI Element:** One-click simulation buttons:
  * `[Simulate Port Scan (Nmap)]`
  * `[Simulate Modbus PLC Sabotage]`
  * `[Simulate SSH Brute Force]`
  * `[Launch Multi-Vector Attack]`
* When clicked, the backend triggers the test container and the user immediately watches the live threat console catch and block it in milliseconds!

#### 5. Hardware & AI Runtime Telemetry Gauges
* **What it does:** Displays system health, CPU temperature, RAM usage, and accelerator status.
* **UI Element:** Live visual gauges displaying:
  * Active Hardware Platform: e.g., `Intel OpenVINO (CPU/NPU)` or `NVIDIA TensorRT (GPU)`
  * Loaded Model: e.g., `version-RFB-320.onnx`
  * Real-time throughput meter: Events Per Second (EPS)

#### 6. Compliance & Forensic Report Exporter
* **What it does:** Generates formal compliance audit documentation on demand.
* **UI Element:** A button `[Generate CMMC / ISO 27001 Audit Report]` that triggers a download of a formatted audit report for regulatory inspectors.

---

### Visual Dashboard Layout Blueprint

```text
+---------------------------------------------------------------------------------------------------------+
| BLACKBOX SENTINEL™                               [STATUS: ACTIVE]   [ENGINE: STOP]   [MODE: ENFORCEMENT] |
+---------------------------------------------------------------------------------------------------------+
|  GAUGES:                                                                                                |
|  [ CPU Temp: 42.0 °C ]    [ RAM: 25.4% (4.1/16GB) ]    [ AI NPU/GPU: 28.5% ]    [ Target: OpenVINO ]   |
+---------------------------------------------------------------------------------------------------------+
|  SIMULATION & DEMO CONTROLS (Click to Test Active Defense):                                             |
|  [ Launch Port Scan ]   [ Launch Modbus Sabotage ]   [ Launch Brute Force ]   [ STOP ALL ATTACKS ]      |
+---------------------------------------------------------------------------------------------------------+
|  LIVE THREAT CONSOLE (Real-Time Ingestion & AI Anomaly Stream):                                         |
|  17:35:10  [CRITICAL]  IP: 172.28.0.250  Score: 0.98  Action: eBPF Drop  (Modbus Coil Write Sabotage)   |
|  17:35:11  [HIGH]      IP: 172.28.0.10   Score: 0.82  Action: Logged     (Auditd SSH Failed Login)      |
|  17:35:12  [INFO]      IP: 172.28.0.20   Score: 0.12  Action: Normal     (Regular PLC Telemetry)        |
+---------------------------------------------------------------------------------------------------------+
|  ACTIVE eBPF KERNEL BLOCKED IPs:                                                                        |
|  IP Address        Blocked At            Trigger Reason                  Actions                        |
|  172.28.0.250      17:35:10 UTC          Unauthorized Modbus Write       [ 1-Click Unblock ]            |
|  172.30.0.252      17:28:44 UTC          High-Concurrency SYN Flood      [ 1-Click Unblock ]            |
+---------------------------------------------------------------------------------------------------------+
|  COMPLIANCE: [ Export CMMC Level 2 Report (PDF) ]        [ Export Raw Forensics Audit (CSV) ]           |
+---------------------------------------------------------------------------------------------------------+
```

---

### Backend REST Endpoints Needed in `src/api/rest_controller.cpp`

To support these interactive controls, the Sentinel C++ REST server handles these actions:

1. `GET /api/v1/status` $\rightarrow$ Returns engine run state, hardware metrics, and active model.
2. `POST /api/v1/control/start` $\rightarrow$ Calls `security_engine.start()`.
3. `POST /api/v1/control/stop` $\rightarrow$ Calls `security_engine.stop()`.
4. `GET /api/v1/blocked-ips` $\rightarrow$ Returns the list of currently blocked IP addresses.
5. `POST /api/v1/unblock-ip` $\rightarrow$ Calls `security_engine.unblock_ip_address(ip)`.
6. `POST /api/v1/simulate-attack` $\rightarrow$ Triggers a background attack script (e.g., Modbus or port scan) for interactive evaluation.

---

### Conclusion

Creating this interactive web application elevates Blackbox Sentinel from a terminal background service into a **commercial turnkey appliance**. It allows you to hand a laptop or tablet to an evaluator or investor and let them test, monitor, and control the entire defense appliance themselves.