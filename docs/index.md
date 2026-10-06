# Blackbox Sentinel (`sentinel` daemon)

**Commercial Cyber-Physical Edge XDR & SIEM Appliance**  
*Tier 3 Foundational Defense Node of the Aryorithm / Blackbox Sentinel Ecosystem*

---

## Executive Architectural Overview

`blackbox-sentinel` is a sovereign, commercial-grade cyber-physical security appliance built in ISO C++20. Operating entirely on-premises with **$0.00 cloud data egress**, it integrates **26 native detection, prevention, and deception subsystems** with **30 industrial protocol dissectors**.

Powered under the hood by **`libblackbox.so`** (Tier 2 in-kernel eBPF/XDP packet mitigation) and **`libxinfer.so`** (Tier 1 heterogeneous AI inference runtime), `blackbox-sentinel` eliminates cloud alerting latency ($15\text{s} - 60\text{s}$) in favor of **sub-microsecond ($< 0.84\,\mu\text{s}$) in-kernel edge drops**.

```text
====================================================================================================
                       BLACKBOX-SENTINEL APPLIANCE ARCHITECTURE
====================================================================================================
 [FLEET COMMAND]            SENTINEL-NEXUS HUB (Tier 6 Central Orchestrator)
                             ▲                │
            gRPC Port 50051  │ Telemetry Sync │ Collective Defense Rules (< 50ms)
                             │ Heartbeats     ▼ OTA Canary Model Rollouts
 ┌───────────────────────────┴────────────────────────────────────────────────────────────────────┐
 │ BLACKBOX-SENTINEL APPLIANCE DAEMON (/usr/local/bin/sentinel)                                   │
 │                                                                                                │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ NexusUplink: Live Telemetry, KernelDropInjector, 0ms Instant Graceful Disconnect         │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ 26 Native C++20 Subsystems (SIEM Core, UEBA, NDR, IDS/IPS, WAF, EDR, CWPP, CPS Sec, DDP) │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                │
 │  ┌──────────────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ 30 Industrial Protocol Dissectors (Modbus, DNP3, S7Comm, PROFINET, DICOM, MAVLink, CAN)   │  │
 │  └──────────────────────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                                │
 │  ┌──────────────────────────────────────────────┐  ┌────────────────────────────────────────┐  │
 │  │ Embedded Web Command Center (Port 8443 HTTPS)│  │ Air-Gapped License Engine (TPM Locked) │  │
 │  │ • Zero External CDNs • Real-Time HTML5 Charts│  │ • 5 Modules Free / 26 Enterprise OT    │  │
 │  └──────────────────────────────────────────────┘  └────────────────────────────────────────┘  │
 └──────────────────────────────┬─────────────────────────────────────────────────────────────────┘
                                │ Under-the-hood in-process bindings
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
 [TIER 2: ACTIVE MITIGATION]                     [TIER 1: AI INFERENCE]
  BLACKBOX-ESSENTIAL (libblackbox.so)             XINFER-ESSENTIAL (libxinfer.so)
  • In-Kernel eBPF/XDP (< 0.84µs Drop SLA)        • Zero-Copy DMA-BUF Memory
  • Lock-Free SPMC RingBuffer (1.25M EPS)         • 15 Silicon Acceleration Targets
  • TPM 2.0 Hardware Attestation                  • Microsecond Residual XAI (< 80ns)
====================================================================================================
```

---

## Core Invariants

1. **Autonomous Operation:** Functions indefinitely when fully air-gapped without external DNS or cloud connectivity.
2. **Sub-Microsecond Mitigation SLA:** Drops cyber-physical threats directly inside the NIC driver ring in **$< 0.84\,\mu\text{s}$**, before socket buffer allocation.
3. **Collective Defense Grid:** Synchronizes zero-day Indicators of Compromise (IoCs) with `sentinel-nexus` in **$< 50\,\text{ms}$** ("Attacked Once, Immune Everywhere").
4. **Air-Gapped Web Command Center:** Serves an embedded administrative management interface on **port 8443** with a **zero-CDN guarantee** (all JavaScript, CSS, and SVG assets are compiled directly into the binary).
5. **Non-Spoofable Hardware Root:** Enforces node identity via physical TPM 2.0 PCR quotes, preventing virtual appliance duplication or unauthorized imaging.

