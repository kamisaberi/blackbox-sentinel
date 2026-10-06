# EtherNet/IP & CIP Dissector (`libsentinel_plugin_enip.so`)

The EtherNet/IP dissector inspects Rockwell Automation (Allen-Bradley) control networks operating on TCP/UDP port **44818**. It parses encapsulation headers and internal Common Industrial Protocol (CIP) commands, validating tag reads, tag writes, and assembly data integrity.

---

## 1. Common Industrial Protocol (CIP) Inspection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ EtherNet/IP Encapsulation Header (24 Bytes)                 │
 │  [ Command: 2B ] [ Length: 2B ] [ Session Handle: 4B ]      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Command: SendRRData / SendUnitData
 ┌─────────────────────────────────────────────────────────────┐
 │ Common Industrial Protocol (CIP) Packet                     │
 │  [ Service: 1B ] [ Path Size: 1B ] [ Request Path: N Bytes ]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Service 0x4C │        │ Service 0x4E │        │ Service 0x0E │
 │ Read Tag     │        │ Write Tag    │        │ Get Attribute│
 │ (Authorized) │        │ (Inspected)  │        │ (Telemetry)  │
 └──────────────┘        └──────┬───────┘        └──────────────┘
                                │ Tag: "ESTOP_BYPASS" == 1
                                ▼
         [ Safety Invariant Breach -> Trigger eBPF Drop ]
```

---

## 2. Threat Vector: Unauthorized CIP Tag Writes

Attackers exploit CIP by submitting unauthenticated `Write Tag` (Service `0x4D` / `0x4E`) requests to manipulate safety logic tags (e.g., `EMERGENCY_STOP_BYPASS` or `PRESSURE_RELIEF_OVERRIDE`). 

`libsentinel_plugin_enip.so` parses symbolic CIP paths in memory and drops unauthorized mutations before the Rockwell ControlLogix controller updates its output table.

