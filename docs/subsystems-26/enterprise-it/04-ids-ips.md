# Subsystem 04: Intrusion Detection & Prevention (`04_ids_ips`)

`04_ids_ips` executes inline pattern matching over packet streams using a SIMD-accelerated **Aho-Corasick automaton**. When an exploit signature matches, it commands Tier 2 `libblackbox` to block the attacker in kernel driver space in $< 0.84\,\mu\text{s}$.

---

## 1. Architectural Pipeline

```text
 [ Ingress Packet Stream ]
            │
            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ SIMD-Accelerated Aho-Corasick Matcher (AVX2 / AVX-512)      │
 │  - Matches 45,000+ Signatures Simultaneously                │
 │  - Scans L4 Payloads in a Single Memory Pass                │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Match Detected                                ▼ Clean Flow
 ┌─────────────────────────────┐                 ┌─────────────┐
 │ Threat Identified (CVE-XXXX)│                 │ Return PASS │
 └──────────────┬──────────────┘                 └─────────────┘
                │
                ▼ Commands Tier 2 Kernel Hook
 ┌─────────────────────────────────────────────────────────────┐
 │ blackbox::XdpManager::block_ip(src_ip, 3600)                │
 │ -> All subsequent packets dropped in < 0.84 µs              │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. In-Kernel Integration

Unlike legacy Snort or Suricata daemons that run in user space and suffer context-switch delays, `04_ids_ips` directly populates the eBPF `blocked_ip_map`. The attacker's network connection is severed before the exploit's second packet reaches the host OS.

