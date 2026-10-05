---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/enip-cip.md`

```markdown
# EtherNet/IP CIP Robotics & Motion Dissector (`libsentinel_plugin_cip_motion.so`)

This dissector provides specialized inspection of **CIP Motion, CIP Safety, and CIP Sync** extensions running on top of EtherNet/IP (TCP/UDP **44818** and UDP **2222**), protecting industrial robotics, automated workcells, and high-speed packaging conveyors.

---

## 1. CIP Safety & Motion Deconstruction

```text
 [ Ingress UDP Port 2222: I/O Real-Time Data Connection ]
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Common Industrial Protocol (CIP) I/O Packet                 │
 │  [ Sequence Number: 2B ] [ 32-Bit Multiplex Header ]        │
 └─────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ CIP Safety PDU                                              │
 │  • Safety Network Number (SNN)                              │
 │  • Time Correction Value (Timestamp Tracking)               │
 │  • Safety CRC-S1 / CRC-S2 Dual Redundant Checks             │
 │  • Estop and Light Curtain Interlock State Bits             │
 └─────────────────────────┬───────────────────────────────────┘
                           │
                           ▼ Violation Detection
 [ Traps Unauthorized Motion Overrides & Safety Interlock Bypasses ]
```

---

## 2. Robotic Axis Protection

* Intercepts `CIP Motion` velocity and position control commands, enforcing speed limits on 6-axis industrial robots.
* Drops packets attempting to clear hardware safety interlocks without authenticated safety supervisor signatures.
```

---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/foundation-fieldbus.md`

```markdown
# FOUNDATION Fieldbus HSE & H1 Dissector (`libsentinel_plugin_fieldbus.so`)

The FOUNDATION Fieldbus dissector inspects process automation communication across oil refineries, chemical reactors, and nuclear processing loops. It analyzes High-Speed Ethernet (HSE) on TCP/UDP ports **1089 / 1090** and H1 field device bridges.

---

## 1. Protocol Architecture & Function Block Execution

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Fieldbus HSE Header: [ PDU Type: 2B ] [ Length: 2B ]        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Function Block Application Protocol (FBAP)                  │
 │  • Resource Block (Hardware Device State)                   │
 │  • Transducer Block (Calibrated Physical Sensors)           │
 │  • Function Block: Analog Input (AI), PID Controller        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Steady-State Telemetry▼ PID Setpoint Change   ▼ Mode Alteration
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Cyclic PV    │        │ Modify SP    │        │ Shift Block  │
 │ (Process Var)│        │ (Inspected)  │        │ Mode to Out- │
 │ (Authorized) │        │              │        │ of-Service   │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Violation Trapped
                                            ▼
               [ Destabilizing Chemical Plant Overrides Blocked ]
```

---

## 2. Preventing Process Runaway

Traps unauthorized transitions of critical PID Function Blocks from **Automatic (`AUTO`)** or **Cascade (`CAS`)** mode into **Manual (`MAN`)** or **Out of Service (`OOS`)**, which attackers use to blind automated safety loops during runaway chemical reactions.
```

---

### Complete in Part 7
- `blackbox-sentinel/docs/plugins-30/energy-utilities/iec-60870-5-104.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/iec-61850-goose.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/iec-61850-mms.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/opc-ua-binary.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/bacnet-ip.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/modbus-rtu-serial.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/enip-cip.md`
- `blackbox-sentinel/docs/plugins-30/energy-utilities/foundation-fieldbus.md`

All 8 Energy, Power Grid & Smart Infrastructure dissectors are now documented.

---

### Files to be Generated in Part 8

The next phase covers **Aviation, Maritime & Sovereign Defense Plugins** (`plugins-30/aviation-maritime-defense/` - 7 files):

1. `plugins-30/aviation-maritime-defense/mavlink-uav.md` (`libmavlink_uav`: Autonomous drone telemetry & GPS spoofing guard)
2. `plugins-30/aviation-maritime-defense/ais-maritime.md` (`libais_maritime`: Commercial shipping transponder collision guard)
3. `plugins-30/aviation-maritime-defense/nmea-gps.md` (`libnmea_gps`: Navigation sensor sentence integrity verifier)
4. `plugins-30/aviation-maritime-defense/ads-b-avionics.md` (`libadsb_avionics`: Air traffic surveillance broadcast validator)
5. `plugins-30/aviation-maritime-defense/stanag-4586.md` (`libstanag_4586`: Military UAV interoperable datalink parser)
6. `plugins-30/aviation-maritime-defense/mil-std-1553.md` (`libmil_std_1553`: Avionics dual-redundant multiplex data bus)
7. `plugins-30/aviation-maritime-defense/canbus-automotive.md` (`libcanbus_automotive`: CAN 2.0B / CAN-FD vehicle ECU frame guard)

Confirm when you are ready to proceed with Part 8.