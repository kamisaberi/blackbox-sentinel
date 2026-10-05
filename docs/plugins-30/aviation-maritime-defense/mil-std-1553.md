---

### File: `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/mil-std-1553.md`

```markdown
# MIL-STD-1553 Avionics Multiplex Data Bus Dissector (`libsentinel_plugin_1553.so`)

The MIL-STD-1553 dissector inspects military avionics telemetry encapsulated over Ethernet/IP (e.g., IRIG-106 Chapter 10 or serialized UDP streams) on UDP port **5553**. It parses Command, Data, and Status words, detecting babbling-idiot bus faults and unauthorized weapons-management commands.

---

## 1. Word Structure & Bus Architecture

MIL-STD-1553 communicates across dual-redundant channels (Bus A / Bus B) using 20-bit Manchester II encoded words:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Encapsulated MIL-STD-1553 Packet (IRIG-106 Chapter 10)      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 20-Bit Word Classification (3-bit Sync, 16-bit Data, 1-bit P)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Command Word          ▼ Data Word             ▼ Status Word
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Remote Term  │        │ 16-Bit Flight│        │ Message Error│
 │ Address: 5B  │        │ Control Data │        │ Busy Flag    │
 │ Subaddress:5B│        │ Payload      │        │ Subsystem    │
 └──────┬───────┘        └──────────────┘        └──────────────┘
        │
        ▼ Traps Reserved Addresses
 ┌─────────────────────────────────────────────────────────────┐
 │ Address 31 (Broadcast Mode) used for Denial-of-Service      │
 │ Illegal Subaddress accessing Weapons Store Management (SMS) │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Avionics Safety Invariants

* **Babbling Idiot Protection:** Intercepts Remote Terminals (RT) that continuously transmit without Bus Controller authorization, dropping their traffic in driver space to keep the bus clear for flight controls.
* **Weapons Management Isolation:** Drops unauthorized Command Words addressed to the Stores Management System (SMS) RT address unless preceded by physical interlock signals.
```

