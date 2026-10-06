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

