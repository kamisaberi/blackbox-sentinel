### Part 3: 26 Native Subsystems — Enterprise IT & Web Protection (`subsystems-26/*`)

This section contains 9 technical implementation guides: the master subsystems dependency matrix, the 5 **Enterprise IT & Detection** modules (`01_siem_core`, `02_ueba`, `03_ndr`, `04_ids_ips`, `15_ngfw`), and the 3 **Web & Application Protection** modules (`05_waf`, `10_bad`, `11_rasp`).

---

### File: `blackbox-sentinel/docs/subsystems-26/index.md`

```markdown
# The 26 Native C++20 Subsystems: Architecture & Dependency Matrix

`blackbox-sentinel` integrates 26 decoupled security modules compiled directly into `sentinel`. Each subsystem operates within an isolated memory envelope and communicates through a lock-free, zero-allocation internal event bus.

---

## 1. Master Subsystems Matrix

| ID | Subsystem Name | Domain Category | Thread Model | Memory Budget | Hardware Dependency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | `01_siem_core` | Enterprise IT | Lock-Free In-Memory Indexer | $512\text{ MB}$ | Host RAM |
| **02** | `02_ueba` | Enterprise IT | 100k-Entity State Matrix | $256\text{ MB}$ | Host RAM |
| **03** | `03_ndr` | Enterprise IT | Zero-Copy Flow Extractor | $128\text{ MB}$ | Tier 1 NPU / CPU |
| **04** | `04_ids_ips` | Enterprise IT | SIMD Aho-Corasick Matcher | $64\text{ MB}$ | Tier 2 eBPF/XDP |
| **05** | `05_waf` | Web App | Zero-Copy HTTP Stream Parser | $64\text{ MB}$ | Tier 2 eBPF/XDP |
| **06** | `06_edr` | Host Endpoint | In-Memory Process Tree Graph | $128\text{ MB}$ | Linux `/proc` & Netlink |
| **07** | `07_epp_ngav` | Host Endpoint | SIMD Shannon Entropy Calculator | $64\text{ MB}$ | AVX2 / ARM Neon |
| **08** | `08_nac` | Identity Access | RADIUS / 802.1X Dynamic Bridge | $32\text{ MB}$ | Linux Netdev Bridge |
| **09** | `09_cwpp` | Host Endpoint | eBPF Syscall Hook Trap | $64\text{ MB}$ | `tracepoint:raw_syscalls` |
| **10** | `10_bad` | Web App | Kinematic Curve Classifier | $32\text{ MB}$ | Tier 1 AI Runtime |
| **11** | `11_rasp` | Web App | In-Memory PLT/GOT Hook Hunter | $16\text{ MB}$ | Process Memory Map |
| **12** | `12_itdr` | Identity Access | Kerberos / LDAP Ticket Inspector | $64\text{ MB}$ | Protocol Dissectors |
| **13** | `13_ddos` | Forensics/Ctrl | In-Kernel SYN Cookie Shaper | $32\text{ MB}$ | Tier 2 eBPF/XDP |
| **14** | `14_ato` | Identity Access | Geo-Velocity Anomaly Engine | $64\text{ MB}$ | Host RAM |
| **15** | `15_ngfw` | Enterprise IT | L7 Protocol State Machine | $128\text{ MB}$ | Protocol Dissectors |
| **16** | `16_cdr` | Host Endpoint | In-Memory Document Sanitizer | $64\text{ MB}$ | Host RAM |
| **17** | `17_iot_sec` | Cyber-Physical | DICOM PACS / HL7 Guard | $64\text{ MB}$ | Protocol Dissectors |
| **18** | `18_cps_sec` | Cyber-Physical | Modbus / DNP3 Physics Guard | $64\text{ MB}$ | Tier 2 eBPF/XDP |
| **19** | `19_swg` | Forensics/Ctrl | Inline DNS/HTTP Sovereign Proxy | $64\text{ MB}$ | Linux epoll Loop |
| **20** | `20_fse` | Host Endpoint | UEFI / BIOS Binary Dissector | $32\text{ MB}$ | TPM 2.0 PCR 0 |
| **21** | `21_side_channel` | Cyber-Physical | Current / Power Waveform FFT | $64\text{ MB}$ | Host ADC / Sensor |
| **22** | `22_dfir` | Forensics/Ctrl | Circular Ring PCAP Evidence Carver | $256\text{ MB}$ | Storage NVMe |
| **23** | `23_ai_trism` | Forensics/Ctrl | Prompt Injection Firewall | $64\text{ MB}$ | Tier 1 AI Runtime |
| **24** | `24_ztna` | Identity Access | Real-Time Session Risk Regressor | $32\text{ MB}$ | Host RAM |
| **25** | `25_fdp` | Forensics/Ctrl | Financial Graph Anomaly Engine | $64\text{ MB}$ | Host RAM |
| **26** | `26_ddp` | Forensics/Ctrl | Decoy Virtual PLC Engine | $64\text{ MB}$ | Secondary VIPs |

---

## 2. Subsystem Coupling & Execution Flow

```text
 [ WIRE INGRESS ] ──► Tier 2 libblackbox (XDP Ingress)
                             │
       ┌─────────────────────┼─────────────────────┐
       ▼                     ▼                     ▼
 [ 13_ddos / 04_ids_ips ] [ 15_ngfw / 03_ndr ]  [ 18_cps_sec / 17_iot_sec ]
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             ▼ Event Normalized
 ┌─────────────────────────────────────────────────────────────┐
 │ 01_siem_core (Central In-Memory Event Indexer)              │
 └─────────────┬───────────────────────────────┬───────────────┘
               │                               │
               ▼                               ▼
       [ 02_ueba Matrix ]              [ 22_dfir PCAP Carver ]
```
```

