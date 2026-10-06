# Autonomous Edge Active Defense & SIEM Appliance Introduction

Traditional Security Information and Event Management (SIEM) and Extended Detection and Response (XDR) architectures rely on forwarding raw logs and PCAP streams to centralized cloud data lakes. In critical infrastructure—such as power substations, semiconductor manufacturing plants, healthcare enclaves, and autonomous naval systems—this paradigm introduces operational failure modes:

* **Latency Latency:** Alerting pipelines take $15 - 60\text{ seconds}$ to ingest, parse, query, and flag incidents, during which an attacker can execute PLC coil overrides or exfiltrate databases.
* **Egress Costs & Bandwidth Saturation:** Pushing terabytes of continuous telemetry over cellular or satellite datalinks incurs thousands of dollars in cloud egress fees.
* **Data Sovereignty Violations:** Regulatory directives (EU NIS 2, CMMC 2.0, HIPAA) strictly forbid routing unencrypted operational technology (OT) payloads through third-party servers.

---

## 1. The Edge Appliance Paradigm

`blackbox-sentinel` is deployed as an on-premises physical appliance (or localized virtual machine) positioned directly on the operational network boundary:

```text
 [ INDUSTRIAL OT / HEALTHCARE ENCLAVE ]
                  │
                  ▼ Ingress Packets (SPAN / TAP / Inline)
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Edge Appliance                            │
 │  - In-Memory Protocol Dissection (< 5 µs)                   │
 │  - Local Microsecond AI Scoring (OpenVINO / TensorRT NPU)   │
 │  - Direct In-Kernel eBPF Drops (< 0.84 µs)                  │
 │  - Embedded On-Appliance SIEM Storage                       │
 └────────────────┬────────────────────────────┬───────────────┘
                  │                            │
                  ▼ Clean Traffic              ▼ Filtered Telemetry Only
          [ Protected PLCs ]           [ Nexus Central Hub ]
```

---

## 2. The 5 Core Operational Stages

The daemon transitions through five execution stages to ensure risk-free onboarding:

1. **`STAGE_SHADOW_MODE` (Passive Audit):** Operates on a network TAP or SPAN port. AI models and protocol parsers score live traffic without dropping any packets.
2. **`STAGE_CANARY_ACTIVE` (Targeted Enforcement):** Enforces in-kernel drops only on high-confidence ($> 0.95$) attack signatures or critical SCADA register tampering.
3. **`STAGE_FULL_ACTIVE` (Autonomous Edge Mitigation):** Inline autonomous protection. Malicious flows are purged in driver memory in $< 0.84\,\mu\text{s}$.
4. **`STAGE_DECEPTION_ACTIVE` (Active Honeypots):** Emulates vulnerable virtual PLC decoys on secondary VIPs to mislead reconnaissance scans.
5. **`STAGE_FORENSIC_LOCKDOWN` (Emergency Air-Gap):** Automatically severs non-critical interfaces while preserving tamper-evident local PCAP evidence.

