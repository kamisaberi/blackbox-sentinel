# PROFINET Real-Time Dissector (`libsentinel_plugin_profinet.so`)

The PROFINET RT dissector analyzes high-speed industrial Ethernet automation frames operating over **EtherType `0x8892`**. It inspects Real-Time (RT) cyclic process data and Acyclic Discovery and Configuration Protocol (DCP) transactions without adding propagation delay to manufacturing motion-control loops.

---

## 1. PROFINET Frame Categorization

```text
 [ Ethernet Frame (EtherType 0x8892) ]
                  │
                  ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Frame ID Classification                                     │
 └────────────────┬────────────────────────────┬───────────────┘
                  │                            │
                  ▼ (0x8000 - 0xBFFF)          ▼ (0xFEFD - 0xFEFF)
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │ PROFINET Cyclic Real-Time   │ │ PROFINET DCP (Discovery)    │
 │  - Cycle Counter Drift      │ │  - Set IP / Reset to Factory│
 │  - DataStatus / IOXCS State │ │  - Station Name Spoofing    │
 └─────────────────────────────┘ └─────────────┬───────────────┘
                                               │ Malicious Reset Trapped
                                               ▼
                         [ Dropped in Kernel Driver before PLC ]
```

---

## 2. Detecting Rogue DCP Factory Resets

Adversaries often weaponize PROFINET Discovery and Basic Configuration Protocol (DCP) to execute unauthenticated denial-of-service attacks:
* **Service `0x04` (Set Request) / Sub-option `0x05` (Reset to Factory Defaults):** When observed outside an active maintenance window, the packet is purged in driver space, preventing line stoppages across automated manufacturing cells.

