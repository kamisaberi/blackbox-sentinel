# 14-Day Zero-Risk Passive SPAN Evaluation (`STAGE_SHADOW_MODE`)

In municipal water plants, nuclear substations, and automotive manufacturing lines, deploying an unverified inline security agent risks unexpected disruption. 

To eliminate operational risk, `blackbox-sentinel` supports **`STAGE_SHADOW_MODE`**: a completely passive evaluation mode designed for 14-day zero-risk network audits.

---

## 1. SPAN Port / Network TAP Topology

```text
 [ Industrial Ethernet Switch ]
        │
        ├── Port 1: Engineering Workstation ──► [ PLC / Field Device ]
        │
        └── Port 8 (SPAN / Mirror Port): Copies 100% of packets
               │
               ▼ Passive Ingress (No Inline Risk)
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Appliance (STAGE_SHADOW_MODE)             │
 │  - Protocol Dissectors decode Modbus / S7 / DNP3            │
 │  - AI Autoencoder scores anomalies in RAM                   │
 │  - Zero Inline Disruption: XDP Filter returns XDP_PASS ONLY │
 │  - Emits XAI Feature Attributions & Compliance Scorecard    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Configuring Shadow Mode

Set the operational stage in `/etc/sentinel/sentinel.yaml`:

```yaml
appliance:
  deployment_stage: "STAGE_SHADOW_MODE"
```

Restart the daemon:

```bash
sudo systemctl restart sentinel
```

---

## 3. Shadow Audit Guarantees

* **Zero Packet Drops:** The in-kernel eBPF filter will **never** return `XDP_DROP`. All packets pass unhindered.
* **Passive Traffic Reflection:** The appliance does not transmit synthetic packets onto the wire unless deception decoys are explicitly enabled.
* **Full Forensic Telemetry:** All 26 native subsystems execute in full evaluation mode. Detections, XAI feature attributions, and anomaly traces are stored in local SIEM memory and visible on the Web Command Center (port 8443).

