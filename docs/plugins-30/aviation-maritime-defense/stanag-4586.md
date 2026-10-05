---

### File: `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/stanag-4586.md`

```markdown
# NATO STANAG 4586 Military UAV Datalink Dissector (`libsentinel_plugin_stanag.so`)

The STANAG 4586 dissector inspects interoperable military unmanned aerial vehicle (UAV) Command and Control (C2) datalinks communicating over UDP/IP port **51000**. It parses Vehicle ID, Command, and Telemetry packets, enforcing strict Level of Interoperability (LOI 1 through 5) authorization boundaries.

---

## 1. STANAG 4586 Packet Deconstruction

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Message Header: [ Sync: 2B ] [ Msg ID: 2B ] [ Length: 2B ]  │
 │                 [ Sequence: 4B ] [ Subsystem ID: 1B ]       │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Message Type Parsing
 ┌─────────────────────────────────────────────────────────────┐
 │ Critical Military UAV Messages:                             │
 │  • Msg 2000: Vehicle Identification                         │
 │  • Msg 2002: Flight Termination Command (CRITICAL)          │
 │  • Msg 2004: Engine Arm / Disarm Command                    │
 │  • Msg 2010: Payload Steering & Target Designation          │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Authorized Station (LOI 4/5)                  ▼ Unauthorized Command
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Cryptographically Signed    │         │ Flight Termination Command  │
 │ Waypoint Update             │         │ Sent from Unverified Station│
 └─────────────────────────────┘         └──────────────┬──────────────┘
                                                        │
                                                        ▼
                        [ Flight Termination Signal Trapped & Purged ]
```

---

## 2. Interoperability Level (LOI) Enforcement

* **LOI 2 (Telemetry Receipt):** Station may read telemetry (Msg 2000 series) but cannot steer sensors.
* **LOI 3 (Payload Control):** Station may steer cameras but cannot command flight dynamics.
* **LOI 4/5 (Flight & Recovery Control):** Commands altering pitch, roll, throttle, or weapon hardpoints require hardware-backed cryptographic signatures. Unsigned commands are dropped immediately.
```

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

---

### File: `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/canbus-automotive.md`

```markdown
# CAN Bus & CAN-FD Automotive Dissector (`libsentinel_plugin_canbus.so`)

The CAN Bus dissector inspects connected-vehicle, heavy equipment, and autonomous automotive networks communicated over SocketCAN interfaces (`can0`, `vcan0`) or Ethernet-to-CAN gateways on UDP port **20001**. It parses standard CAN 2.0B (11/29-bit IDs) and CAN-FD frames (up to 64-byte payloads), identifying bus-off injection attacks and unauthorized braking/steering overrides.

---

## 1. Frame Architecture & Dissection Pipeline

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Linux SocketCAN Frame (struct can_frame / canfd_frame)      │
 │  [ can_id: 4B (11/29-Bit Arbitration ID) ]                  │
 │  [ can_dlc: 1B (Payload Length 0-8 or 0-64) ]               │
 │  [ data: Up to 64 Bytes ]                                   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Arbitration ID Classification (J1939 / UDS / Proprietary)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Diagnostic (UDS)      ▼ Critical Motion (ADAS)▼ Telemetry
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ ID 0x7DF:    │        │ Steering /   │        │ Tire Pressure│
 │ Service 0x27 │        │ Braking Torq │        │ Climate Ctrl │
 │ SecurityAccess│       │ (Tampering)  │        │ (Passive)    │
 └──────┬───────┘        └──────┬───────┘        └──────────────┘
        │                       │
        └───────────┬───────────┘
                    │ Threat Confirmed
                    ▼
 [ Injected Frame Blocked -> Vehicle Control Loop Protected ]
```

---

## 2. In-Memory Attack Signatures Trapped

* **Unified Diagnostic Services (UDS) Injection:** Intercepts unauthorized Service `0x27` (Security Access) and Service `0x2E` (Write Data by Identifier) attempting to reflash Engine Control Unit (ECU) firmware while the vehicle is in motion ($v > 0\,\text{km/h}$).
* **Bus-Off Flood Attacks:** Detects high-frequency arbitration ID `0x000` dominant bit floods designed to force legitimate ECUs into the error-passive bus-off state.
```

---

### Complete in Part 8
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/mavlink-uav.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/ais-maritime.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/nmea-gps.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/ads-b-avionics.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/stanag-4586.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/mil-std-1553.md`
- `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/canbus-automotive.md`

All 7 Aviation, Maritime & Sovereign Defense dissectors are now documented.

---

### Files to be Generated in Part 9

The next phase covers **Healthcare Diagnostic & SIEM Forwarder Plugins** (`plugins-30/healthcare-and-siem/` - 8 files):

1. `plugins-30/healthcare-and-siem/dicom-pacs.md` (`libdicom_pacs`: 16-bit radiology imaging & C-STORE payload guard)
2. `plugins-30/healthcare-and-siem/hl7-v2.md` (`libhl7_v2`: Clinical patient diagnostic message structure verifier)
3. `plugins-30/healthcare-and-siem/cef-forwarder.md` (`libcef_forwarder`: Common Event Format SIEM stream exporter)
4. `plugins-30/healthcare-and-siem/leef-forwarder.md` (`libleef_forwarder`: IBM QRadar Log Event Extended Format exporter)
5. `plugins-30/healthcare-and-siem/syslog-rfc5424.md` (`libsyslog_rfc5424`: Structured cryptographic syslog forwarder)
6. `plugins-30/healthcare-and-siem/kafka-producer.md` (`libkafka_producer`: Zero-copy high-throughput enterprise streaming)
7. `plugins-30/healthcare-and-siem/snmp-v3-trap.md` (`libsnmp_v3_trap`: Encrypted SNMP operational alert forwarder)
8. `plugins-30/healthcare-and-siem/netflow-v9-ipfix.md` (`libnetflow_v9_ipfix`: Line-rate NetFlow telemetry export engine)

Confirm when you are ready to proceed with Part 9.