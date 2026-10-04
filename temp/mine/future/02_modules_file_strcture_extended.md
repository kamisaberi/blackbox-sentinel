Here is the complete, exhaustive master file structure for **Blackbox Sentinel**, detailing every single file across all 10 isolated modules, configuration directories, core orchestrator components, web command center assets, deployment scripts, and test suites.

---

### Master File Structure: `blackbox-sentinel/`

```text
blackbox-sentinel/
├── CMakeLists.txt                               # Root build script with modular feature toggles
├── LICENSE                                      # Commercial Enterprise License
├── README.md                                    # Comprehensive Product Documentation
│
├── configs/                                     # System Configuration Files
│   ├── sentinel_config.json                     # Main appliance configuration
│   ├── default_rules.json                       # Global correlation rules
│   └── modules/                                 # Subsystem-Specific JSON Configurations
│       ├── ndr.json                             # NDR flow thresholds & ETA parameters
│       ├── edr.json                             # Host agent monitoring policies
│       ├── cwpp.json                            # Container eBPF syscall rules
│       ├── waf.json                             # Web API payload inspection rules
│       ├── ueba.json                            # User behavioral baseline thresholds
│       ├── cps_ot.json                          # Industrial SCADA/PLC physics parameters
│       ├── ddp.json                             # Honeypot decoy port bindings
│       ├── dfir.json                            # Rolling PCAP memory buffer size
│       ├── itdr.json                            # Active Directory / Kerberos rules
│       └── ai_trism.json                        # LLM prompt firewall rules
│
├── include/
│   └── sentinel/                                # Public Framework & Interface Headers
│       ├── sentinel.hpp                         # Master single-include product header
│       ├── module_interface.hpp                 # ISentinelModule abstract interface
│       ├── event_bus.hpp                        # Lock-free decoupled Pub/Sub Event Bus
│       ├── config_manager.hpp                   # Dynamic JSON settings loader header
│       ├── plugin.hpp                           # ISentinelPlugin commercial plugin interface
│       └── plugin_manager.hpp                   # SentinelPluginManager dlopen loader header
│
├── src/
│   ├── main.cpp                                 # Sentinel Daemon main entry point
│   │
│   ├── core/                                    # Daemon Orchestration & Internal Bus
│   │   ├── orchestrator.hpp                     # Master module lifecycle coordinator header
│   │   ├── orchestrator.cpp                     # Starts and stops modules dynamically
│   │   ├── event_bus.cpp                        # In-memory lock-free event bus implementation
│   │   └── config_manager.cpp                   # Global JSON settings loader implementation
│   │
│   ├── api/                                     # Embedded Management Server & REST API
│   │   ├── auth_manager.hpp                     # User authentication & RBAC header
│   │   ├── auth_manager.cpp                     # JWT tokens & role validation implementation
│   │   ├── rest_controller.hpp                  # REST API controller & file server header
│   │   ├── rest_controller.cpp                  # REST endpoints & static web server implementation
│   │   ├── ws_streamer.hpp                      # Real-time WebSocket streamer header
│   │   └── ws_streamer.cpp                      # Live incident WebSocket broadcaster
│   │
│   ├── hardware/                                # Hardware Security & Telemetry
│   │   ├── hw_monitor.hpp                       # CPU/GPU/NPU sensor monitor header
│   │   ├── hw_monitor.cpp                       # Linux /proc telemetry implementation
│   │   ├── tpm_license.hpp                      # TPM 2.0 / Hardware node identity header
│   │   └── tpm_license.cpp                      # Adaptive TPM/vTPM/fallback validator
│   │
│   ├── exporter/                                # Compliance & Forensic Audit Exporter
│   │   ├── report_generator.hpp                 # CMMC / ISO 27001 report generator header
│   │   └── report_generator.cpp                 # PDF & CSV compliance audit builder
│   │
│   └── modules/                                 # 10 ISOLATED SUBSYSTEM MODULES
│       │
│       ├── ndr/                                 # [Module 1: Network Detection & Response]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── ndr_module.hpp                   # NDR module lifecycle header
│       │   ├── ndr_module.cpp                   # NDR module registration
│       │   ├── flow_analyzer.hpp                # NetFlow / IPFIX flow inspector header
│       │   ├── flow_analyzer.cpp                # 10Gbps flow feature builder implementation
│       │   ├── eta_fingerprinter.hpp            # Encrypted Traffic Analysis header
│       │   └── eta_fingerprinter.cpp            # TLS packet size/timing fingerprinter
│       │
│       ├── edr/                                 # [Module 2: Endpoint Detection & Response]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── edr_module.hpp                   # EDR module lifecycle header
│       │   ├── edr_module.cpp                   # EDR module registration
│       │   ├── process_tracker.hpp              # Host process tree analyzer header
│       │   ├── process_tracker.cpp              # Process execution tree tracker implementation
│       │   ├── memory_scanner.hpp               # In-memory beacon hunter header
│       │   ├── memory_scanner.cpp               # Volatile process memory inspector
│       │   ├── file_integrity.hpp               # File integrity monitoring (FIM) header
│       │   └── file_integrity.cpp               # Real-time file modification detector
│       │
│       ├── cwpp/                                # [Module 3: Container eBPF Syscall Guard]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── cwpp_module.hpp                  # CWPP module lifecycle header
│       │   ├── cwpp_module.cpp                  # CWPP module registration
│       │   ├── syscall_evaluator.hpp            # Kernel syscall tensor evaluator header
│       │   ├── syscall_evaluator.cpp            # eBPF kprobe/tracepoint tensor scorer
│       │   ├── container_watcher.hpp            # Docker/K8s namespace monitor header
│       │   └── container_watcher.cpp            # Container breakout detector implementation
│       │
│       ├── waf/                                 # [Module 4: Web App & API Defense]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── waf_module.hpp                   # WAF module lifecycle header
│       │   ├── waf_module.cpp                   # WAF module registration
│       │   ├── http_payload_eval.hpp            # HTTP payload evaluator header
│       │   ├── http_payload_eval.cpp            # Sub-millisecond SQLi/XSS tensor scorer
│       │   ├── api_logic_inspector.hpp          # API business logic inspector header
│       │   └── api_logic_inspector.cpp          # BOLA/IDOR API exploit detector
│       │
│       ├── ueba/                                # [Module 5: Behavioral Analytics Engine]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── ueba_module.hpp                  # UEBA module lifecycle header
│       │   ├── ueba_module.cpp                  # UEBA module registration
│       │   ├── behavior_matrix.hpp              # In-memory user state matrix header
│       │   ├── behavior_matrix.cpp              # 100k+ concurrent user tracker implementation
│       │   ├── anomaly_scorer.hpp               # Statistical deviation calculator header
│       │   └── anomaly_scorer.cpp               # Gaussian/LSTM anomaly scorer implementation
│       │
│       ├── cps_ot/                              # [Module 6: Industrial SCADA Defense]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── cps_module.hpp                   # CPS module lifecycle header
│       │   ├── cps_module.cpp                   # CPS module registration
│       │   ├── physics_validator.hpp            # Physical process constraint validator header
│       │   ├── physics_validator.cpp            # Pressure/RPM physics limits evaluator
│       │   ├── modbus_parser.hpp                # Modbus TCP protocol parser header
│       │   ├── modbus_parser.cpp                # Modbus function code inspector implementation
│       │   ├── dnp3_parser.hpp                  # DNP3 substation protocol parser header
│       │   └── dnp3_parser.cpp                  # DNP3 command validator implementation
│       │
│       ├── ddp/                                 # [Module 7: Active Deception Honeypots]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── ddp_module.hpp                   # DDP module lifecycle header
│       │   ├── ddp_module.cpp                   # DDP module registration
│       │   ├── decoy_ports.hpp                  # Fake service listener header
│       │   ├── decoy_ports.cpp                  # Emulated SSH/Telnet/Web trap implementation
│       │   ├── honeypot_trap.hpp                # Honeypot alert dispatcher header
│       │   └── honeypot_trap.cpp                # Instant eBPF trigger on decoy access
│       │
│       ├── dfir/                                # [Module 8: Forensics & Evidence Carver]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── dfir_module.hpp                  # DFIR module lifecycle header
│       │   ├── dfir_module.cpp                  # DFIR module registration
│       │   ├── pcap_ring_buffer.hpp             # Rolling PCAP memory buffer header
│       │   ├── pcap_ring_buffer.cpp             # 60s pre/post-breach packet buffer implementation
│       │   ├── evidence_signer.hpp              # Chain-of-custody cryptographic signer header
│       │   └── evidence_signer.cpp              # SHA-256 / Ed25519 evidence signature implementation
│       │
│       ├── itdr/                                # [Module 9: Identity & Active Directory]
│       │   ├── CMakeLists.txt                   # Module build configuration
│       │   ├── itdr_module.hpp                  # ITDR module lifecycle header
│       │   ├── itdr_module.cpp                  # ITDR module registration
│       │   ├── kerberos_watcher.hpp             # Kerberos ticket inspector header
│       │   ├── kerberos_watcher.cpp             # Kerberoasting & ticket manipulation detector
│       │   ├── ad_analyzer.hpp                  # Active Directory event analyzer header
│       │   └── ad_analyzer.cpp                  # Privilege escalation detector implementation
│       │
│       └── ai_trism/                            # [Module 10: AI Prompt Firewall]
│           ├── CMakeLists.txt                   # Module build configuration
│           ├── ai_trism_module.hpp              # AI TRiSM module lifecycle header
│           ├── ai_trism_module.cpp              # AI TRiSM module registration
│           ├── prompt_sanitizer.hpp             # LLM prompt injection filter header
│           ├── prompt_sanitizer.cpp             # Sub-millisecond prompt sanitizer implementation
│           ├── leak_detector.hpp                # PII and API secret leak detector header
│           └── leak_detector.cpp                # Output token stream inspector implementation
│
├── web/                                         # Air-Gapped Single-Page Web Application
│   ├── index.html                               # Command center main layout
│   ├── favicon.ico                              # Local browser icon
│   │
│   ├── assets/                                  # Static Visual Branding (Zero External CDNs)
│   │   ├── logo.svg                             # Sentinel vector emblem
│   │   └── icons.svg                            # Bundled SVG sprite map
│   │
│   ├── css/                                     # Modular Dark-Theme Stylesheets
│   │   ├── theme.css                            # Global color tokens & typography
│   │   ├── components.css                       # Buttons, badges, modals, and tables
│   │   └── dashboard.css                        # Metrics gauges & live console styling
│   │
│   └── js/                                      # Modular JavaScript Controllers & Clients
│       ├── app.js                               # Master application entry point
│       ├── api.js                               # REST API client wrapper (port 8443)
│       ├── websocket.js                         # WebSocket telemetry client (port 8444)
│       │
│       └── controllers/                         # Dedicated Feature Controllers
│           ├── engine_control.js                # Start / Stop engine toggle controller
│           ├── threat_console.js                # Real-time live threat feed renderer
│           ├── ebpf_table.js                    # eBPF blocked IP table manager (1-click unblock)
│           ├── simulator.js                     # Attack simulation trigger controller
│           ├── metrics_gauge.js                 # Hardware telemetry gauge updater
│           └── compliance.js                    # CMMC / ISO 27001 report downloader
│
├── deploy/                                      # Deployment Automation & System Services
│   ├── install_appliance.sh                     # Bare-metal turnkey installer script
│   ├── sentinel.service                         # Linux systemd service unit file
│   │
│   ├── docker/                                  # Multi-Device Simulation Environment
│   │   └── docker-compose.massive.yml           # 12-container simulation testbed
│   │
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
    └── benchmark_system.cpp                     # Full appliance microsecond latency benchmarker
```

---

### Key Architectural Safeguards in this Structure

1. **Self-Contained Module Folders (`src/modules/*/`):** Every module has its own `CMakeLists.txt`, lifecycle headers, and internal implementations. Deleting or disabling an entire module folder will not cause compilation errors in any other module.
2. **Dedicated Configurations (`configs/modules/*.json`):** Individual JSON configuration files ensure that tuning thresholds for one subsystem (e.g. `ndr.json`) never corrupts settings for another (e.g. `cps_ot.json`).
3. **Decoupled Event Bus (`include/sentinel/event_bus.hpp`):** Modules communicate strictly through asynchronous event publishing and subscriptions (`blackbox::SecurityEvent`), avoiding any direct header cross-inclusion.