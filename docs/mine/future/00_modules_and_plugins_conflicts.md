To prevent collisions, race conditions, memory corruption, and duplicate processing across **26 modules** and **30 plugins**, we must establish a formal **Architectural Boundary**.

The most common failure in large security architectures is treating modules and plugins as the same thing. If a module and a plugin both attempt to bind to the same network port, alter the same event state, or hook into the Linux kernel simultaneously, the appliance will crash or suffer severe packet drops.

Below is the conflict-prevention audit, defining the exact distinction between modules and plugins, the mapping matrix, and the five architectural safeguards ensuring zero conflict.

---

### 1. The Core Boundary: Modules vs. Plugins

| Dimension | **Internal Subsystem Module (`src/modules/*`)** | **Dynamic Extension Plugin (`src/plugins/*`)** |
| :--- | :--- | :--- |
| **Architectural Role** | **The Core Brain / Discipline:** Owns state, correlation logic, user-configured policies, and lifecycle management. | **The Sensor / Adapter / Protocol Dissector:** Implements specific protocol parsing or external API integrations. |
| **Compilation** | Compiled statically or linked internally into the `sentinel` daemon binary via CMake toggles. | Compiled as standalone shared objects (`.so`) loaded at runtime via Linux `dlopen()`. |
| **Event Authority** | Can make high-level decisions (escalate threat scores, mandate mitigations, alter user states). | Can only annotate events with metadata or parse raw byte streams. Plugins **never** override module policy. |
| **Communication** | Subscribes and publishes to the internal C++ `EventBus`. | Interfaced directly by its parent module or by the `SentinelPluginManager`. |

---

### 2. Module-to-Plugin Ownership Matrix (Eliminating Duplication)

The 30 plugins do **not** compete with the 26 modules; rather, **each plugin is an pluggable driver feeding a specific module**. 

The matrix below maps each of the 30 plugins directly to its governing module:

| Governing Module (`src/modules/*`) | Supported Dynamic Plugins (`src/plugins/*`) | How Conflict is Prevented |
| :--- | :--- | :--- |
| **`01_siem_core`** (SIEM Ingestion & Storage) | `sentinel_plugin_cef_forwarder` (\#07)<br>`sentinel_plugin_webhook` (\#20) | Plugins act strictly as egress exporters. They format and push alerts to Splunk/Slack without touching ingestion queues. |
| **`02_ueba`** (Behavioral Analytics) | `sentinel_plugin_ueba_analytics` (\#14) | The plugin extracts user session metadata; the module maintains the 100k+ in-memory state matrix. |
| **`03_ndr`** (Network Detection & Response) | `sentinel_plugin_eta_traffic` (\#13) | The module captures raw 10Gbps packets; the plugin calculates TLS packet size/timing fingerprints without SSL decryption. |
| **`04_ids_ips`** (Intrusion Prevention) | `sentinel_plugin_dns_tunneling` (\#16) | The plugin unpacks DNS queries; the module compares domain entropy against rule thresholds. |
| **`05_waf`** (Web Application & API Defense) | `sentinel_plugin_admin_portal_trap` (\#25) | The plugin serves decoy HTTP endpoints; the module inspects valid API payloads. |
| **`06_edr`** (Endpoint Detection & Response) | `sentinel_plugin_auditd_reconstructor` (\#24) | The plugin parses raw Linux Auditd strings; the module tracks the host process parentage tree. |
| **`08_nac`** (Network Access Control) | `sentinel_plugin_firewall_sync` (\#08) | The module calculates device isolation requirements; the plugin talks to external Palo Alto/Fortinet APIs. |
| **`10_bad`** (Bot Abuse Defense) | `sentinel_plugin_active_deception` (\#02) | The plugin listens on decoy ports; the module calculates mouse/keystroke behavioral entropy. |
| **`12_itdr`** (Identity Threat Detection) | `sentinel_plugin_ad_correlator` (\#15) | The plugin queries LDAP/Kerberos databases; the module evaluates privilege escalation graphs. |
| **`17_iot_sec`** (IoT / Medical Security) | `sentinel_plugin_dicom_medical` (\#29)<br>`sentinel_plugin_hl7_hospital` (\#30) | The plugins decode DICOM/HL7 protocol headers; the module evaluates protocol anomaly scores. |
| **`18_cps_sec`** (Industrial SCADA OT) | `sentinel_plugin_scada_modbus` (\#01)<br>`sentinel_plugin_dnp3_grid` (\#04)<br>`sentinel_plugin_profinet` (\#06)<br>`sentinel_plugin_s7comm` (\#11)<br>`sentinel_plugin_bacnet` (\#19) | The module evaluates physical constraints (turbine RPM, chemical valves); the plugins dissect specific vendor PLC protocols. |
| **`22_dfir`** (Forensics & Evidence) | `sentinel_plugin_pcap_carver` (\#03)<br>`sentinel_plugin_evidence_locker` (\#22)<br>`sentinel_plugin_memory_dump` (\#23) | The module triggers forensic actions; the plugins execute raw PCAP carving, Ed25519 cryptographic signing, and memory dumps. |
| **`23_ai_trism`** (AI Security / LLM) | `sentinel_plugin_llm_summarizer` (\#09) | The module filters malicious prompt injections; the plugin writes human-readable forensic briefs. |
| **`26_ddp`** (Distributed Deception) | `sentinel_plugin_plc_decoy` (\#21)<br>`sentinel_plugin_canary_file` (\#26) | The module manages deception strategy; the plugins run the fake Siemens PLC honeypot and canary files. |
| **Facilities Convergence Subsystem** | `sentinel_plugin_rtsp_correlator` (\#05)<br>`sentinel_plugin_gpio_siren` (\#12)<br>`sentinel_plugin_onvif_tamper` (\#27) | The module handles vision camera bounding boxes; the plugins drive GPIO physical siren relays and ONVIF stream checks. |
| **Tactical & Maritime Subsystem** | `sentinel_plugin_mavlink` (\#10)<br>`sentinel_plugin_stanag_link16` (\#17)<br>`sentinel_plugin_ais_maritime` (\#18)<br>`sentinel_plugin_nmea_marine` (\#28) | The module evaluates operational coordinates; the plugins parse drone MAVLink, NATO Link 16, AIS, and NMEA marine streams. |

---

### 3. The 5 Architectural Safeguards Against Conflicts

To maintain high performance and prevent system collisions, the software enforces five structural rules:

#### Safeguard 1: Unidirectional Event Pipeline (No Circular Loops)
A common hazard in multi-module architectures is an infinite loop (e.g., Module A publishes an event $\rightarrow$ Module B modifies it and republishes $\rightarrow$ Module A catches it again).

Blackbox Sentinel enforces a strict **one-way sequential pipeline**. Events move strictly forward through five phases:

```text
[ PHASE 1: INGESTION & DISSECTION ]
- Plugins parse incoming raw streams (Modbus, Syslog, RTSP, MAVLink)
               |
               v
[ PHASE 2: TENSOR EXTRACTION & INFERENCE ]
- Raw features are converted into float vectors and evaluated by libxinfer.so
               |
               v
[ PHASE 3: CORRELATION & MODULE STATE ]
- Modules evaluate policies (UEBA, ITDR, CPS-Sec physics rules, RulesEngine)
               |
               v
[ PHASE 4: KERNEL MITIGATION ]
- If anomaly score >= threshold, eBPF/XDP drops the IP at the NIC level
               |
               v
[ PHASE 5: EGRESS & EXPORT ]
- Plugins export events (Splunk CEF, PagerDuty, PCAP Carver, SQLite DB)
```
Events cannot loop backward. Once an event enters Phase 5, it is purged from memory.

---

#### Safeguard 2: Network Port & Socket Binding Arbitration
Conflicts occur when two components try to bind to the same TCP/UDP port (e.g., Module `18_cps_sec` inspecting port 502 vs. Plugin `sentinel_plugin_plc_decoy` listening on port 502).

* **Inspection Rule (Passive & Inline):** Ingestion drivers (`network_ingest.cpp`, `ndr`, `ids_ips`, `cps_sec`) **never bind to user-space ports**. They inspect packets using Linux `AF_XDP` or raw promiscuous sockets.
* **Deception Rule (Honeypots):** Deception plugins (`sentinel_plugin_active_deception`, `sentinel_plugin_plc_decoy`) only bind to **dedicated virtual/secondary IP addresses (VIPs)** assigned to the honeypot interface, never to the primary appliance management IP.

---

#### Safeguard 3: C++ Namespace Isolation
To prevent duplicate symbol errors during compilation and linking, every module and plugin is scoped inside distinct, nested namespaces:

* Modules: `sentinel::modules::<module_name>::*` (e.g., `sentinel::modules::ndr::FlowAnalyzer`)
* Plugins: `sentinel::plugins::<plugin_name>::*` (e.g., `sentinel::plugins::scada_modbus::ModbusDissector`)
* Core Engine: `sentinel::core::*`
* Base Library: `blackbox::*` and `xinfer::*`

Global functions or un-namespaced classes are strictly disallowed.

---

#### Safeguard 4: Dynamic Linker Isolation (`RTLD_LOCAL`)
When `SentinelPluginManager` loads a plugin via `dlopen()`, using `RTLD_GLOBAL` can cause plugins with shared internal helper libraries (e.g., two plugins using different versions of an XML or JSON parser) to overwrite each other's symbols in memory.

Blackbox Sentinel enforces **`RTLD_LAZY | RTLD_LOCAL`** in `plugin_manager.cpp`:
```cpp
void* handle = dlopen(plugin_so_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
```
`RTLD_LOCAL` ensures that symbols defined within `libplugin_scada_modbus.so` are isolated from `libplugin_pcap_carver.so`, preventing dynamic symbol clashes.

---

#### Safeguard 5: Immutable Event State Pattern
When a `SecurityEvent` struct is pushed through the lock-free `EventBus`, multiple modules may inspect it concurrently in separate threads.

To eliminate race conditions:
* Telemetry data (source IP, port, timestamp, feature vectors) is **read-only**.
* Modules can only write to their own dedicated output slots within the event struct:
  ```cpp
  struct SecurityEvent {
      // Read-only telemetry
      const std::string source_ip;
      const uint16_t port;
      const std::vector<float> features;

      // Module-specific annotation slots (Mutex-protected)
      float ai_anomaly_score;
      float ueba_risk_score;
      float cps_physics_delta;
      ThreatLevel final_decision_level;
  };
  ```
No module can overwrite another module's score, eliminating data races.

---

### Summary Checklist

1. **No Duplicate Execution:** Modules govern behavioral logic; plugins govern protocol parsing.
2. **No Port Collisions:** Production traffic is read via raw sockets; honeypots listen only on separate decoy IP addresses.
3. **No Build Collisions:** Each of the 26 modules has its own `CMakeLists.txt` toggle (`-DSENTINEL_ENABLE_01_SIEM=ON`, etc.), allowing selective compilation of only the modules you need.
4. **No Memory Conflicts:** Plugins are loaded with `RTLD_LOCAL` to ensure clean symbol isolation in memory.