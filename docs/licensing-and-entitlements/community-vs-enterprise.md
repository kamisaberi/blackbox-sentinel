# Module Entitlement Matrix: Community Edition vs. Enterprise OT

`blackbox-sentinel` ships with a permanently free, air-gapped **Community Edition** alongside commercial **Enterprise OT** and **Mission-Critical Defense** license tiers.

---

## 1. Feature & Subsystem Availability Matrix

| Subsystem ID & Name | Community Edition (Free) | Enterprise OT | Mission-Critical Defense |
| :--- | :--- | :--- | :--- |
| **`01_siem_core`** (In-Memory Log Correlation) | **Included** | **Included** | **Included** |
| **`02_ueba`** (Entity Behavior Analytics) | Not Included | **Included** (100k Entities) | **Included** (Unlimited) |
| **`03_ndr`** (Network Detection & TLS JA3) | **Included** | **Included** | **Included** |
| **`04_ids_ips`** (Aho-Corasick & eBPF Drops) | **Included** | **Included** | **Included** |
| **`05_waf`** (Web Application & API Protection)| **Included** | **Included** | **Included** |
| **`06_edr`** (Endpoint Process Tree & Injection)| Not Included | **Included** | **Included** |
| **`07_epp_ngav`** (Shannon Entropy Ransomware) | **Included** | **Included** | **Included** |
| **`08_nac`** (802.1X Dynamic VLAN Quarantine) | Not Included | **Included** | **Included** |
| **`09_cwpp`** (Container eBPF Syscall Guard) | Not Included | **Included** | **Included** |
| **`10_bad`** (Kinematic Bot Defense) | Not Included | **Included** | **Included** |
| **`11_rasp`** (In-Memory PLT/GOT Protection) | Not Included | **Included** | **Included** |
| **`12_itdr`** (Kerberoasting & AD Defense) | Not Included | **Included** | **Included** |
| **`13_ddos`** (In-Kernel SYN Cookie Shaper) | Not Included | **Included** | **Included** |
| **`14_ato`** (Account Takeover & Geo-Velocity)| Not Included | **Included** | **Included** |
| **`15_ngfw`** (Layer 7 Stateful Deep Packet) | Not Included | **Included** | **Included** |
| **`16_cdr`** (Content Disarm & Macro Stripper)| Not Included | **Included** | **Included** |
| **`17_iot_sec`** (Medical DICOM PACS & HL7) | Not Included | **Included** | **Included** |
| **`18_cps_sec`** (SCADA Modbus Physical Guard) | Not Included | **Included** | **Included** |
| **`19_swg`** (Sovereign Outbound Egress Proxy)| Not Included | **Included** | **Included** |
| **`20_fse`** (UEFI / BIOS Firmware Evaluator) | Not Included | **Included** | **Included** |
| **`21_side_channel`** (Power / Waveform FFT) | Not Included | Not Included | **Included** |
| **`22_dfir`** (Circular PCAP Evidence Vault) | Not Included | **Included** | **Included** |
| **`23_ai_trism`** (AI Safety & Prompt Firewall)| Not Included | **Included** | **Included** |
| **`24_ztna`** (Real-Time Risk Regressor) | Not Included | **Included** | **Included** |
| **`25_fdp`** (Financial Graph Anomaly Engine) | Not Included | Not Included | **Included** |
| **`26_ddp`** (Decoy PLCs on Secondary VIPs) | Not Included | **Included** | **Included** |

---

## 2. Dissectors & Capabilities Summary

* **Community Edition (5 Core Modules):** Permanently free for personal labs, educational research, and small deployments. Provides `siem_core`, `ndr`, `ids_ips`, `waf`, and `epp_ngav` with in-kernel eBPF drops.
* **Enterprise OT (All 26 Modules + 30 Dissectors):** Unlocks full industrial SCADA protection (Modbus, S7, DNP3, PROFINET), medical PACS, deception honeypots, and $< 50\,\text{ms}$ Collective Defense grid synchronization.
* **Mission-Critical Defense:** Adds side-channel power analysis, financial transaction graphs, military avionics parsers (MIL-STD-1553, STANAG-4586), and dedicated custom driver engineering SLAs.

