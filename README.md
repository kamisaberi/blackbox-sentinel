# Blackbox Sentinel: Autonomous Cyber-Physical XDR & SIEM Platform

Blackbox Sentinel is an air-gapped, sub-millisecond Active Extended Detection and Response (XDR) and Security Information and Event Management (SIEM) software appliance. Built in native C++20 and powered by the `libblackbox.so` security kernel and the `libxinfer.so` universal AI runtime, Sentinel unifies 26 decoupled security modules and 30 dynamic commercial plugins into an air-gapped, zero-cloud platform.

By coupling deep learning inference directly to Linux kernel eBPF/XDP (eXpress Data Path) drivers, Blackbox Sentinel mitigates network intrusions, industrial SCADA overrides, and physical perimeter breaches in microseconds directly in hardware and kernel memory.

---

## Architecture Stack

Blackbox Sentinel operates as Layer 3 in a decoupled, three-tier architecture:

```text
===================================================================================
 LAYER 3: BLACKBOX SENTINEL (Commercial Product Application & XDR Platform)
 - 26 Decoupled Subsystem Modules (SIEM, NDR, EDR, CWPP, WAF, UEBA, CPS-Sec, etc.)
 - 30 Dynamic Commercial Extension Plugins (SCADA Modbus, PCAP Carver, etc.)
 - Air-Gapped Web Command Center Dashboard (Port 8443) & WebSocket Streamer (Port 8444)
 - Adaptive Hardware Identity Engine (Physical TPM 2.0 / VMware vTPM / Host UUID)
 - Automated CMMC Level 2 & ISO 27001 Forensic Audit Exporter
===================================================================================
                                         |
                                         v (Links against libblackbox.so)
===================================================================================
 LAYER 2: LIBBLACKBOX.SO (Core Active Security Engine)
 - Native eBPF / XDP Sub-Microsecond Kernel IP Packet Dropper (xdp_drop.o)
 - Decoupled Lock-Free Ring Buffer & Event Bus
 - Multi-Modal Cyber-Physical Threat Correlator
 - Encrypted Local SQLite / RocksDB Audit Database
===================================================================================
                                         |
                                         v (Links against libxinfer.so)
===================================================================================
 LAYER 1: LIBXINFER.SO (Universal C++20 AI Runtime)
 - 15 Hardware Acceleration Targets (TensorRT, OpenVINO, RKNN, QNN, Vitis AI, etc.)
 - Zero-Copy DMA-BUF, NVMM, and Pinned Memory Allocators
 - Automatic HTTPS ONNX Model Hub & Dynamic C++ AI Plugin Manager
===================================================================================
```

---

## 26 Decoupled Security Modules

Every major capability within Blackbox Sentinel is implemented as an independent module under `src/modules/` implementing the `ISentinelModule` interface. Modules communicate asynchronously through a central lock-free `EventBus`, preventing tight coupling or compile-time conflicts.

| # | Module Name | Directory | Primary Security Mission | Technical Mechanism |
| :-: | :--- | :--- | :--- | :--- |
| **01** | **SIEM Core** | `src/modules/01_siem_core/` | Log aggregation, time-series forecasting, and cross-source correlation. | Evaluates event volume curves and correlates multi-source telemetry in memory. |
| **02** | **UEBA** | `src/modules/02_ueba/` | User & Entity Behavior Analytics. | Maintains live behavioral state matrices for 100k+ concurrent identities without GC pauses. |
| **03** | **NDR** | `src/modules/03_ndr/` | Network Detection & Response / Encrypted Traffic Analysis. | Inspects raw packet headers and TLS metadata (JA3/JA4) at 10Gbps line rate without SSL decryption. |
| **04** | **IDS / IPS** | `src/modules/04_ids_ips/` | Inline signature matching and anomaly packet dropping. | Direct kernel XDP hooks evaluate signatures and drop malicious packets before OS allocation. |
| **05** | **WAF / WAAP** | `src/modules/05_waf/` | Web Application & API Protection. | Evaluates HTTP request tensors for SQLi, XSS, and BOLA/IDOR exploits in $<1\,\text{ms}$. |
| **06** | **EDR** | `src/modules/06_edr/` | Endpoint Detection & Response. | Tracks host process parentage trees, unmapped executable memory, and reflective DLL injections. |
| **07** | **EPP / NGAV** | `src/modules/07_epp_ngav/` | Next-Gen Antivirus & Ransomware IOPS Interceptor. | Calculates Shannon entropy of file writes in real time to kill encryption threads before data loss. |
| **08** | **NAC** | `src/modules/08_nac/` | Network Access Control. | Classifies connected hardware via DHCP/packet handshakes to enforce automated 802.1X/VLAN quarantine. |
| **09** | **CWPP** | `src/modules/09_cwpp/` | Cloud Workload Protection & Container Guard. | Attaches eBPF kprobes to `sys_enter` to evaluate syscall sequence tensors and prevent container escape. |
| **10** | **BAD** | `src/modules/10_bad/` | Bot & Automated Abuse Defense. | Neural networks analyze mouse velocity, keystroke dynamics, and TCP fingerprints to stop automated bots. |
| **11** | **RASP** | `src/modules/11_rasp/` | Runtime Application Self-Protection. | Injected C++ shared library inside app runtimes intercepts memory hooks and malicious query calls. |
| **12** | **ITDR** | `src/modules/12_itdr/` | Identity Threat Detection & Response. | Detects Kerberoasting, ticket manipulation, and Active Directory privilege escalation. |
| **13** | **DDoS Mitigation** | `src/modules/13_ddos/` | Hardware line-rate flood mitigation. | Shapes and drops SYN/UDP floods inside the NIC driver at line-rate before OS memory allocation. |
| **14** | **ATO** | `src/modules/14_ato/` | Account Takeover Defense. | Evaluates login velocity, geo-velocity (impossible travel), and device fingerprints to block credential stuffing. |
| **15** | **NGFW** | `src/modules/15_ngfw/` | Next-Generation Firewall Deep Packet Inspection. | Uses deep learning models to classify application protocols and unknown tunnels at wire speed. |
| **16** | **CDR** | `src/modules/16_cdr/` | Content Disarm & Reconstruction. | Parses binary file structures (PDF/DOCX) in memory, strips weaponized macros, and reconstructs clean files. |
| **17** | **IoT / IoMT Sec** | `src/modules/17_iot_sec/` | Embedded IoT & Medical Device Defense. | Monitors medical imaging and telemetry protocols (DICOM, HL7) for buffer exploits and tampering. |
| **18** | **CPS-Sec** | `src/modules/18_cps_sec/` | Cyber-Physical & SCADA OT Defense. | Evaluates incoming Modbus/DNP3 commands against physical equipment constraints (pressure, RPM limits). |
| **19** | **SWG** | `src/modules/19_swg/` | Secure Web Gateway. | Sits inline as a transparent proxy to classify zero-minute phishing URLs and malicious payloads. |
| **20** | **FSE** | `src/modules/20_fse/` | Firmware Security Evaluation. | Disassembles UEFI/BIOS binary firmware images to identify static code flaws and backdoors. |
| **21** | **Side-Channel** | `src/modules/21_side_channel/` | Hardware Side-Channel Physical Defense. | Analyzes microsecond power draw fluctuations and electromagnetic noise to detect physical cryptanalysis. |
| **22** | **DFIR** | `src/modules/22_dfir/` | Digital Forensics & Incident Response. | Maintains rolling 10GB in-memory packet buffer; carves 60s pre/post-breach PCAP evidence automatically. |
| **23** | **AI TRiSM** | `src/modules/23_ai_trism/` | AI Trust, Risk & LLM Prompt Firewall. | Reverse-proxy evaluating LLM prompt token streams to block prompt injection and proprietary PII/API key leaks. |
| **24** | **ZTNA** | `src/modules/24_ztna/` | Zero Trust Network Access. | Continuously recalculates device trust scores to adjust micro-segmentation access rules dynamically. |
| **25** | **FDP** | `src/modules/25_fdp/` | Fraud Detection & Prevention. | Real-time graph analytics and tensor scoring of financial transactions to spot synthetic IDs and fraud. |
| **26** | **DDP** | `src/modules/26_ddp/` | Distributed Deception (Honeypot Grid). | Deploys decoy PLCs, fake SSH listeners, and honey tokens; probing triggers immediate eBPF drops. |

---

## 30 Dynamic Commercial Add-On Plugins

Blackbox Sentinel supports dynamic `.so` plugins loaded via `SentinelPluginManager` using Linux `dlopen()`. These plugins provide protocol-specific inspectors, enterprise bridges, and forensic extensions without recompiling the core daemon.

| # | Plugin Target Name | File Location `(src/plugins/*)` | Add-On Package | Functional Description |
| :-: | :--- | :--- | :--- | :--- |
| **01** | `sentinel_plugin_scada_modbus` | `scada_modbus_plugin.cpp` | Industrial OT Pack | Decodes Modbus TCP function codes; drops unauthorized coil/register writes. |
| **02** | `sentinel_plugin_active_deception`| `active_deception_plugin.cpp` | Enterprise Pack | Emulates decoy ports (2222, 23, 8080); interaction triggers instant eBPF drop. |
| **03** | `sentinel_plugin_pcap_carver` | `pcap_carver_plugin.cpp` | Enterprise Pack | Carves 60-second raw PCAP window before/after high-severity alerts into an evidence file. |
| **04** | `sentinel_plugin_dnp3_grid` | `dnp3_grid_plugin.cpp` | Industrial OT Pack | Inspects DNP3 and IEC 60870-5-104 substation telemetry on ports 20000/2404. |
| **05** | `sentinel_plugin_rtsp_correlator` | `rtsp_vision_correlator_plugin.cpp`| Facilities Pack | Correlates YOLO camera bounding box events with network anomalies in $<1\,\text{ms}$. |
| **06** | `sentinel_plugin_profinet` | `profinet_inspector_plugin.cpp` | Industrial OT Pack | Inspects real-time PROFINET and EtherNet/IP communications in assembly lines. |
| **07** | `sentinel_plugin_cef_forwarder` | `cef_forwarder_plugin.cpp` | Enterprise Pack | Streams normalized threat alerts upstream to central Splunk/QRadar clusters over TLS. |
| **08** | `sentinel_plugin_firewall_sync` | `firewall_sync_plugin.cpp` | Enterprise Pack | Pushes eBPF blocked IP lists to external Palo Alto / Fortinet firewalls via REST API. |
| **09** | `sentinel_plugin_llm_summarizer` | `llm_summarizer_plugin.cpp` | Enterprise Pack | Runs local quantized LLMs via `xinfer` to write air-gapped incident summaries. |
| **10** | `sentinel_plugin_mavlink` | `mavlink_inspector_plugin.cpp` | Defense & UAV Pack | Decodes MAVLink drone streams; flags GPS spoofing, jamming, and control hijacking. |
| **11** | `sentinel_plugin_s7comm` | `s7comm_opcua_plugin.cpp` | Industrial OT Pack | Detects unauthorized Siemens S7 ladder-logic uploads and OPC UA browsing. |
| **12** | `sentinel_plugin_gpio_siren` | `gpio_siren_plugin.cpp` | Facilities Pack | Actuates physical sirens, strobe lights, and door locks upon critical threat events. |
| **13** | `sentinel_plugin_eta_traffic` | `eta_traffic_plugin.cpp` | Enterprise Pack | Identifies malware in encrypted TLS traffic using packet size and timing signatures. |
| **14** | `sentinel_plugin_ueba_analytics` | `ueba_analytics_plugin.cpp` | Enterprise Pack | Establishes statistical baselines for users; flags off-hours data exfiltration. |
| **15** | `sentinel_plugin_ad_correlator` | `src/plugins/ad_correlator_plugin.cpp` | Enterprise Pack | Maps raw IP/MAC addresses to Active Directory usernames and Kerberos tickets. |
| **16** | `sentinel_plugin_dns_tunneling` | `src/plugins/dns_tunneling_plugin.cpp` | Enterprise Pack | Detects C2 communications hidden inside DNS queries using domain entropy models. |
| **17** | `sentinel_plugin_stanag_link16` | `src/plugins/stanag_link16_plugin.cpp` | Defense & UAV Pack | Validates NATO STANAG 4586 and Link 16 tactical data links for message corruption. |
| **18** | `sentinel_plugin_ais_maritime` | `src/plugins/ais_maritime_plugin.cpp` | Defense & UAV Pack | Monitors AIS vessel position telemetry to detect spoofing and dark fleet activity. |
| **19** | `sentinel_plugin_bacnet` | `src/plugins/bacnet_inspector_plugin.cpp` | Industrial OT Pack | Monitors BACnet IP protocols controlling HVAC, elevators, and building access. |
| **20** | `sentinel_plugin_webhook` | `src/plugins/webhook_dispatcher_plugin.cpp` | Enterprise Pack | Dispatches real-time incident payloads to PagerDuty, Slack, Teams, or webhooks. |
| **21** | `sentinel_plugin_plc_decoy` | `src/plugins/plc_decoy_plugin.cpp` | Industrial OT Pack | Emulates Siemens or Rockwell PLCs on unused IPs to lure and trap industrial attackers. |
| **22** | `sentinel_plugin_evidence_locker`| `src/plugins/evidence_locker_plugin.cpp` | Defense & UAV Pack | Signs forensic evidence files with SHA-256 and Ed25519 for legal chain-of-custody. |
| **23** | `sentinel_plugin_memory_dump` | `src/plugins/memory_dump_plugin.cpp` | Enterprise Pack | Triggers volatile RAM memory dumps of compromised host processes on critical alerts. |
| **24** | `sentinel_plugin_auditd_reconstructor`| `src/plugins/auditd_reconstructor_plugin.cpp`| Enterprise Pack | Reconstructs process parentage and file modifications from Linux Auditd streams. |
| **25** | `sentinel_plugin_admin_portal_trap`| `src/plugins/admin_portal_trap_plugin.cpp`| Enterprise Pack | Serves fake router/firewall login portals; unauthorized login attempts trigger eBPF drops. |
| **26** | `sentinel_plugin_canary_file` | `src/plugins/canary_file_plugin.cpp` | Enterprise Pack | Places fake token files on servers; alerts and isolates processes when accessed. |
| **27** | `sentinel_plugin_onvif_tamper` | `src/plugins/onvif_tamper_plugin.cpp` | Facilities Pack | Flags camera video blinding, signal cutting, or RTSP stream injection attacks. |
| **28** | `sentinel_plugin_nmea_marine` | `src/plugins/nmea_marine_plugin.cpp` | Defense & UAV Pack | Protects ship navigation systems, gyros, and depth sounders from cyber manipulation. |
| **29** | `sentinel_plugin_dicom_medical` | `src/plugins/dicom_medical_plugin.cpp` | Healthcare Pack | Inspects PACS hospital medical imaging protocols for ransomware and data tampering. |
| **30** | `sentinel_plugin_hl7_hospital` | `src/plugins/hl7_hospital_plugin.cpp` | Healthcare Pack | Validates patient health records and medical IoT device data streams for zero-day attacks. |

---

## Repository Layout

```text
blackbox-sentinel/
├── CMakeLists.txt                               # Root build script with 26 module toggles
├── LICENSE                                      # Commercial Enterprise License
├── README.md                                    # Master Product Manual
│
├── configs/                                     # Global & Subsystem Settings
│   ├── sentinel_config.json                     # Main appliance configuration
│   ├── default_rules.json                       # Global correlation rules
│   └── modules/                                 # 26 Dedicated Module Configurations
│       ├── siem_core.json                       # SIEM correlation thresholds
│       ├── ueba.json                            # User behavioral parameters
│       ├── ndr.json                             # 10Gbps flow parameters
│       └── ... (Configs for all 26 modules)
│
├── include/
│   └── sentinel/                                # Framework Master Interfaces
│       ├── sentinel.hpp                         # Master single-include header
│       ├── module_interface.hpp                 # ISentinelModule abstract interface
│       ├── event_bus.hpp                        # Lock-free Pub/Sub Event Bus
│       ├── config_manager.hpp                   # Dynamic settings loader
│       ├── plugin.hpp                           # Commercial plugin interface
│       └── plugin_manager.hpp                   # Dynamic .so loader (dlopen / dlsym)
│
├── src/
│   ├── main.cpp                                 # Sentinel Appliance daemon entry point
│   ├── core/                                    # Orchestrator & Event Bus (Micro-Kernel)
│   │   ├── orchestrator.hpp / .cpp              # Module lifecycle manager
│   │   ├── event_bus.cpp                        # Lock-free in-memory event router
│   │   └── config_manager.cpp                   # Global JSON settings loader
│   ├── api/                                     # Web Server & REST/WebSocket Engine
│   │   ├── auth_manager.hpp / .cpp              # User authentication & RBAC
│   │   ├── rest_controller.hpp / .cpp           # REST API & static web file server
│   │   └── ws_streamer.hpp / .cpp               # Real-time WebSocket broadcaster
│   ├── hardware/                                # Hardware Security & Telemetry
│   │   ├── hw_monitor.hpp / .cpp                # CPU temp, RAM, and NPU utilization
│   │   └── tpm_license.hpp / .cpp               # Adaptive TPM 2.0 / vTPM / Fallback identity
│   ├── exporter/                                # Compliance Exporter
│   │   ├── report_generator.hpp / .cpp          # CMMC Level 2 / ISO 27001 audit builder
│   ├── plugins/                                 # 30 Dynamic Commercial Plugin Implementations
│   │   ├── scada_modbus_plugin.cpp              # Modbus TCP inspector plugin
│   │   ├── active_deception_plugin.cpp          # Decoy honeypot trap plugin
│   │   └── ... (All 30 plugin source files)
│   └── modules/                                 # 26 Decoupled Subsystem Modules
│       ├── 01_siem_core/                        # Module 1: SIEM Core Log Correlation
│       ├── 02_ueba/                             # Module 2: User Behavior Analytics
│       ├── 03_ndr/                              # Module 3: Network Traffic Analysis
│       ├── 04_ids_ips/                          # Module 4: Intrusion Prevention
│       ├── 05_waf/                              # Module 5: Web API Defense
│       ├── 06_edr/                              # Module 6: Host Endpoint Defense
│       ├── 07_epp_ngav/                         # Module 7: Antivirus File Entropy
│       ├── 08_nac/                              # Module 8: Network Access Control
│       ├── 09_cwpp/                             # Module 9: Container eBPF Guard
│       ├── 10_bad/                              # Module 10: Bot Abuse Defense
│       ├── 11_rasp/                             # Module 11: Runtime App Self-Protection
│       ├── 12_itdr/                             # Module 12: Identity Threat Detection
│       ├── 13_ddos/                             # Module 13: Hardware DDoS Mitigation
│       ├── 14_ato/                              # Module 14: Account Takeover Defense
│       ├── 15_ngfw/                             # Module 15: Firewall Deep Packet Inspection
│       ├── 16_cdr/                              # Module 16: Content Disarm & Reconstruction
│       ├── 17_iot_sec/                          # Module 17: IoT & Medical Device Defense
│       ├── 18_cps_sec/                          # Module 18: SCADA OT Cyber-Physical Defense
│       ├── 19_swg/                              # Module 19: Secure Web Gateway
│       ├── 20_fse/                              # Module 20: Firmware Security Evaluation
│       ├── 21_side_channel/                     # Module 21: Hardware Side-Channel Defense
│       ├── 22_dfir/                             # Module 22: Forensics & Evidence Carver
│       ├── 23_ai_trism/                         # Module 23: LLM Prompt Firewall
│       ├── 24_ztna/                             # Module 24: Zero Trust Network Access
│       ├── 25_fdp/                              # Module 25: Fraud Detection & Prevention
│       └── 26_ddp/                              # Module 26: Distributed Deception Honeypots
│
├── web/                                         # Air-Gapped Web Command Center
│   ├── index.html                               # Single-Page Application (SPA) shell
│   ├── favicon.ico                              # Local browser icon
│   ├── assets/                                  # Static branding assets (Zero CDNs)
│   │   ├── logo.svg                             # Sentinel vector emblem
│   │   └── icons.svg                            # Bundled SVG sprite map
│   ├── css/                                     # Modular Dark-Theme Stylesheets
│   │   ├── theme.css                            # Global color tokens & typography
│   │   ├── components.css                       # Buttons, badges, modals, and tables
│   │   └── dashboard.css                        # Metrics gauges & live console styling
│   └── js/                                      # Modular JavaScript Controllers
│       ├── app.js                               # Master application entry point
│       ├── api.js                               # REST API client wrapper (port 8443)
│       ├── websocket.js                         # WebSocket telemetry client (port 8444)
│       └── controllers/                         # Dedicated Feature Controllers
│           ├── engine_control.js                # Start / Stop engine toggle controller
│           ├── threat_console.js                # Real-time live threat feed renderer
│           ├── ebpf_table.js                    # eBPF blocked IP table manager (1-click unblock)
│           ├── simulator.js                     # Attack simulation trigger controller
│           ├── metrics_gauge.js                 # Hardware telemetry gauge updater
│           └── compliance.js                    # CMMC / ISO 27001 report downloader
│
├── deploy/                                      # Deployment Automation & Services
│   ├── install_appliance.sh                     # Bare-metal turnkey installer script
│   ├── sentinel.service                         # Linux systemd service unit file
│   ├── docker/
│   │   └── docker-compose.massive.yml           # 12-container simulation testbed
│   └── scripts/                                 # Operational Management Scripts
│       ├── launch_sentinel.sh                   # Startup wrapper script
│       ├── stop_sentinel.sh                     # Graceful shutdown script
│       ├── simulate_attack.sh                   # Quick attack test script
│       ├── attack_console.py                    # Interactive attack controller console
│       └── massive_stress_test.sh               # 100k+ EPS stress testing script
│
└── tests/                                       # Modular Test Suite & Benchmarks
    ├── CMakeLists.txt                           # Tests build configuration
    ├── test_orchestrator.cpp                    # Module orchestrator lifecycle test
    ├── test_event_bus.cpp                       # Event bus concurrency and throughput test
    └── benchmark_system.cpp                     # Full appliance latency benchmarker
```

---

## Hardware Specifications & Deployment Tiers

Blackbox Sentinel is commercially deployed in three hardware form factors:

| Metric / Feature | **Tier A: Tactical Node** | **Tier B: Enterprise 1U Server** | **Tier C: Industrial DIN-Rail** |
| :--- | :--- | :--- | :--- |
| **Target Environment** | Military vehicles, UAVs, naval ships | Data centers, utilities, bank vaults | SCADA plants, electrical substations |
| **Chassis / Form Factor** | Fanless IP67 ruggedized enclosure | 1U 19-inch rackmount chassis | Ruggedized DIN-rail industrial box |
| **Processor Architecture** | NVIDIA Jetson Orin / Rockchip RK3588 | Intel Core Ultra / Xeon / AMD EPYC | Low-power ARM Cortex-A76 + NPU |
| **Memory Capacity** | 16\,GB – 32\,GB LPDDR5 | 64\,GB – 192\,GB DDR5 ECC | 8\,GB – 16\,GB Industrial RAM |
| **Hardware Accelerators** | Integrated 6–40 TOPS NPU/CUDA | NVIDIA RTX / Intel NPU (30+ TOPS) | Integrated 6 TOPS NPU Core |
| **Network Interfaces** | 4x 1GbE RJ45 (eBPF accelerated) | 4x 10GbE/25GbE SFP+ (AF_XDP zero-copy)| 2x 1GbE RJ45 + RS-485 Serial |
| **Power Consumption** | $<25$\,W (Battery / Solar compatible)| 150\,W – 350\,W Redundant AC | $<15$\,W Industrial DC (12–24V) |
| **Hardware Security** | Discrete TPM 2.0 / Secure Boot | Hardware TPM 2.0 / Chassis Intrusion | Encrypted eMMC / Hardware Watchdog |

---

## Installation & Build Instructions

### Prerequisites
- Operating System: Ubuntu 22.04 / 24.04 LTS, Debian 12, or Yocto Immutable Linux
- Compiler: GCC 10+ or Clang 12+ (C++20 compliant)
- CMake 3.20+
- System Dependencies: `libssl-dev`, `libsqlite3-dev`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `pkg-config`
- Core Libraries: `libxinfer.so` and `libblackbox.so` installed in `/usr/local/lib`

### 1. Build and Install Dependencies

```bash
# 1. Install Ubuntu system build dependencies
sudo apt-get update && sudo apt-get install -y \
    build-essential cmake clang llvm \
    libssl-dev libsqlite3-dev libbpf-dev libelf-dev zlib1g-dev \
    tpm2-tools libtss2-dev

# 2. Verify shared libraries are registered in system cache
sudo ldconfig
ls -la /usr/local/lib/libxinfer.so /usr/local/lib/libblackbox.so
```

### 2. Configure and Compile Blackbox Sentinel

```bash
cd /home/kami/blackbox-sentinel
mkdir -p build && cd build

# Configure CMake with all desired module toggles
cmake .. -DSENTINEL_ENABLE_01_SIEM=ON \
         -DSENTINEL_ENABLE_02_UEBA=ON \
         -DSENTINEL_ENABLE_03_NDR=ON \
         -DSENTINEL_ENABLE_04_IDS_IPS=ON \
         -DSENTINEL_ENABLE_05_WAF=ON \
         -DSENTINEL_ENABLE_06_EDR=ON \
         -DSENTINEL_ENABLE_07_EPP_NGAV=ON \
         -DSENTINEL_ENABLE_08_NAC=ON \
         -DSENTINEL_ENABLE_09_CWPP=ON \
         -DSENTINEL_ENABLE_13_DDOS=ON \
         -DSENTINEL_ENABLE_18_CPS_SEC=ON \
         -DSENTINEL_ENABLE_22_DFIR=ON \
         -DSENTINEL_ENABLE_26_DDP=ON

# Compile Sentinel daemon and commercial plugins
make -j$(nproc)

# Install binaries and system services
sudo make install
```

---

## Operational Commands

### Starting the Appliance

To start Sentinel using the automated launcher:
```bash
sudo ./scripts/launch_sentinel.sh
```

Or run the compiled binary directly:
```bash
sudo ./build/sentinel
```

To run as a persistent system daemon:
```bash
sudo systemctl enable --now sentinel
sudo systemctl status sentinel
```

### Stopping the Appliance

To stop the daemon cleanly (flushes SQLite databases, detaches eBPF filters, and terminates child processes):
```bash
sudo ./scripts/stop_sentinel.sh
```

Or send a termination signal:
```bash
sudo pkill -2 sentinel
```

---

## Air-Gapped Web Command Center

Blackbox Sentinel bundles an embedded HTTP and WebSocket server. Operators can access the management interface directly via browser:

```text
URL: http://localhost:8443
```

### Frontend Capabilities:
1. **Appliance Control:** One-click `[STOP ENGINE]` / `[START ENGINE]` toggles with visual operational badges.
2. **Hardware Telemetry:** Live gauges displaying CPU temperature, RAM usage, NPU load, and active AI engine.
3. **Attack Simulator Panel:** Interactive buttons to trigger simulated Nmap scans, Modbus sabotage, and SSH brute-force floods.
4. **Live Threat Console:** Real-time log streamer rendering anomaly events with sub-millisecond timestamps.
5. **Interactive eBPF Table:** Live list of dropped IPs with instant `[1-CLICK UNBLOCK]` overrides.
6. **Compliance Exporter:** On-demand downloads of CMMC Level 2 and ISO 27001 audit reports.

---

## REST API Specification

All REST endpoints are served on port 8443 by default:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/system-health` | Returns hardware metrics (CPU, RAM, NPU load) and recent threat logs in JSON. |
| `POST` | `/api/v1/control/start` | Starts the active defense engine. |
| `POST` | `/api/v1/control/stop` | Pauses the active defense engine. |
| `POST` | `/api/v1/unblock-ip` | Body: `{"ip_address": "1.2.3.4"}`. Removes IP from kernel eBPF drop map. |
| `POST` | `/api/v1/simulate-attack`| Body: `{"attack_type": "nmap|modbus|ssh|multi"}`. Triggers simulated test vectors. |

---

## Benchmark Metrics Summary

Evaluated on an Intel Core i9-14900K workstation (192\,GB RAM, Intel 10GbE NIC) running a sustained load of 100,000,000 security events:

```text
=================================================================================
Blackbox Sentinel Performance Benchmark Summary
Engine Dependencies : libblackbox.so (eBPF Kernel) + libxinfer.so (OpenVINO NPU)
=================================================================================
Average Mitigation Latency  : 0.84 microseconds (us) (< 1.0 ms end-to-end)
Minimum Latency             : 0.12 microseconds (us)
P95 Latency                 : 0.92 microseconds (us)
P99 Latency                 : 1.05 microseconds (us)
Peak Event Throughput       : 1,250,000 Events Per Second (EPS)
Idle / Max RAM Footprint    : 180 MB / 1.38 GB
CPU Utilization @ 100k EPS  : 8.2% (32 Threads)
Active Kernel Packet Drop   : Nanosecond Wire-Speed (XDP_DROP)
=================================================================================
```

---

## License

Blackbox Sentinel is commercial proprietary software. Copyright (c) 2026 Kamran Saberifard. All rights reserved. See `LICENSE` for commercial terms, support agreements, and OEM distribution licensing.