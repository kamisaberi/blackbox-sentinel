# Per-Module Tuning Parameters & Memory Budgets

Each of the 26 subsystems in `blackbox-sentinel` exposes modular configuration blocks under the `subsystems` key in `sentinel.yaml`.

---

## 1. Subsystem Configuration Blocks

```yaml
subsystems:
  # ----------------------------------------------------------------------------
  # 01: SIEM Core In-Memory Log Indexer
  # ----------------------------------------------------------------------------
  siem_core:
    enabled: true
    ring_slots: 1048576              # 1M pre-allocated in-memory event slots
    index_retention_hours: 24        # Rolling in-memory query window
    max_query_results: 1000

  # ----------------------------------------------------------------------------
  # 02: User & Entity Behavior Analytics (UEBA)
  # ----------------------------------------------------------------------------
  ueba:
    enabled: true
    max_tracked_entities: 100000     # Pre-allocated entity state buckets
    baseline_learning_hours: 168     # 7 days baseline moving window
    anomaly_zscore_threshold: 3.5    # Standard deviations triggering alert
    risk_score_mitigate_threshold: 85.0 # Composite score triggering eBPF drop

  # ----------------------------------------------------------------------------
  # 04: Intrusion Detection & Prevention (IDS/IPS)
  # ----------------------------------------------------------------------------
  ids_ips:
    enabled: true
    signature_set_path: "/opt/sentinel/rules/suricata_ot.rules"
    aho_corasick_case_sensitive: false
    auto_block_severity_threshold: 4 # Drop only Severity 4 (Critical) exploits

  # ----------------------------------------------------------------------------
  # 07: Next-Gen Antivirus & Shannon Entropy Blocker (EPP/NGAV)
  # ----------------------------------------------------------------------------
  epp_ngav:
    enabled: true
    monitored_mountpoints: ["/home", "/var/www", "/opt"]
    entropy_threshold: 7.85          # Flag files with Shannon entropy >= 7.85 bits/byte
    iops_burst_threshold: 15         # Max high-entropy writes/sec per process

  # ----------------------------------------------------------------------------
  # 13: Line-Rate Flood Shaper & SYN Cookie Guard (DDoS)
  # ----------------------------------------------------------------------------
  ddos:
    enabled: true
    syn_flood_pps_threshold: 50000   # Triggers in-kernel eBPF SYN cookies
    udp_per_ip_pps_threshold: 5000   # Token bucket rate limit per source IPv4
    icmp_pps_threshold: 1000         # Drops excessive ICMP echo storms

  # ----------------------------------------------------------------------------
  # 26: Distributed Deception Platform (DDP Decoys)
  # ----------------------------------------------------------------------------
  ddp:
    enabled: true
    virtual_ip_interfaces:
      - alias_ip: "10.240.0.199"
        mac_address: "00:50:56:A1:B2:C3"
        emulated_device: "SCHNEIDER_M340_PLC"
        listening_ports: [502, 80]
      - alias_ip: "10.240.0.200"
        mac_address: "00:50:56:A1:B2:C4"
        emulated_device: "SIEMENS_S7_1200"
        listening_ports: [102, 443]
```

---

## 2. Memory Sizing Invariants

Modifying state matrix parameters scales memory requirements deterministically during startup:

$$\text{RAM}_{\text{UEBA}} = \text{max\_tracked\_entities} \times 2{,}048\,\text{bytes} = 100{,}000 \times 2\,\text{KB} \approx 200\,\text{MB}$$

All memory is pre-allocated on initialization; changing parameters requires restarting the daemon.

