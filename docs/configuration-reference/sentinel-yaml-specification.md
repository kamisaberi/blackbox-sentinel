# Exhaustive `sentinel.yaml` Configuration Specification

All operational parameters for `blackbox-sentinel` are declared in `/etc/sentinel/sentinel.yaml`. The daemon's internal `ConfigManager.cpp` parses this document at launch, strips inline comments (`#`), and validates types against internal schemas.

---

## 1. Master Configuration Schema

```yaml
version: "1.0.0"

# ==============================================================================
# 1. APPLIANCE ROOT IDENTITY & LIFECYCLE
# ==============================================================================
appliance:
  node_name: "edge-substation-alpha" # Unique string identifier across the fleet
  deployment_stage: "STAGE_FULL_ACTIVE" # STAGE_SHADOW_MODE, STAGE_CANARY_ACTIVE, STAGE_FULL_ACTIVE, STAGE_DECEPTION_ACTIVE, STAGE_FORENSIC_LOCKDOWN
  log_level: "INFO"                  # TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
  telemetry_interval_sec: 5          # Polling period for telemetry aggregation
  enable_crash_handler: true         # Intercepts SIGSEGV/SIGBUS and writes core stacktrace
  max_memory_mb: 2048                # Hard ceiling on total process virtual memory

# ==============================================================================
# 2. IN-KERNEL NETWORK FAST PATH (TIER 2 BINDINGS)
# ==============================================================================
network:
  primary_interface: "eth0"          # Target network adapter (e.g. eth0, ens33, vmxnet3)
  promiscuous_mode: true             # Opens socket in promiscuous packet capture mode
  xdp_attach_mode: "DRIVER"          # DRIVER (Native <0.84µs), SKB (Generic fallback), HW (Offload)
  bpf_filter_path: "/usr/local/lib/bpf/xdp_filter.o"
  max_blocked_ips: 65536             # Pre-allocated capacity of in-kernel blocked_ip_map
  ring_buffer_capacity: 131072       # SPMC lock-free queue capacity (Must be power of two)
  enable_af_xdp_zerocopy: true       # Bypasses kernel sk_buff allocation using direct UMEM
  xsk_queue_id: 0                    # Hardware RX queue ID bound to primary worker

# ==============================================================================
# 3. AI INFERENCE ENGINE (TIER 1 BINDINGS)
# ==============================================================================
ai_runtime:
  model_path: "/opt/sentinel/models/network_threat_v2.onnx"
  target_backend: "AUTO"             # AUTO, OPENVINO, TENSORRT, RKNN, CPU_REFERENCE
  precision: "FP16"                  # FP32, FP16, INT8
  device_id: 0                       # Hardware accelerator ordinal index
  enable_zero_copy: true             # Uses host-pinned and direct DMA memory pointers
  batch_size: 1                      # Deterministic single-frame evaluation
  shadow_model_path: ""              # Optional path for parallel Canary evaluation

# ==============================================================================
# 4. HARDWARE SILICON ROOT OF TRUST (TPM 2.0)
# ==============================================================================
hardware_identity:
  enforce_tpm: true                  # Refuses launch if physical/virtual TPM is absent
  tpm_device_path: "/dev/tpmrm0"     # In-kernel Resource Manager device path
  pcr_selection: [0, 4]              # PCR 0 (Firmware) and PCR 4 (Bootloader/Kernel)
  enable_anti_cloning: true          # Monitors monotonic counters to detect VM clones

# ==============================================================================
# 5. EMBEDDED WEB COMMAND CENTER (PORT 8443)
# ==============================================================================
web_console:
  enabled: true                      # Embedded HTTPS administrative console
  bind_address: "0.0.0.0"
  port: 8443
  max_connections: 64
  session_timeout_minutes: 30
  ssl_certificate: "/etc/sentinel/certs/server.crt"
  ssl_private_key: "/etc/sentinel/certs/server.key"
  rate_limit_rps: 100

# ==============================================================================
# 6. CENTRAL FLEET ORCHESTRATION (NEXUS UPLINK)
# ==============================================================================
nexus_uplink:
  enabled: true                      # Connects to Tier 6 Sentinel-Nexus Hub
  hub_address: "10.240.0.10"
  hub_port: 50051
  heartbeat_interval_sec: 5
  tls_enabled: true
  ca_certificate: "/etc/sentinel/certs/nexus_ca.crt"
  client_certificate: "/etc/sentinel/certs/appliance.crt"
  client_private_key: "/etc/sentinel/certs/appliance.key"
  reconnect_backoff_max_sec: 30

# ==============================================================================
# 7. FORENSIC VAULT & STORAGE
# ==============================================================================
storage:
  evidence_vault_path: "/var/log/sentinel/forensics"
  pcap_ring_duration_seconds: 30     # Continuous pre-attack ring buffer depth
  max_vault_storage_gb: 50           # Auto-prunes oldest signed PCAPs when exceeded
```

---

## 2. Validation Utility

Validate syntax and variable types before reloading:

```bash
sentinel --validate-config /etc/sentinel/sentinel.yaml
```

