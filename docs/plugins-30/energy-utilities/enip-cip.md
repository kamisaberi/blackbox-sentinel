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

