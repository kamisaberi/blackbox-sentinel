---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/bacnet-ip.md`

```markdown
# BACnet/IP Smart Building Dissector (`libsentinel_plugin_bacnet.so`)

The BACnet/IP dissector monitors building management systems (BMS), commercial HVAC controllers, fire alarms, and physical access entry points operating over UDP port **47808 (`0xBAC0`)**. It decodes BACnet Virtual Link Control (BVLC) and APDU layers to detect environmental sabotage and unauthorized access control overrides.

---

## 1. Packet Topology & Dissection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ BVLL Header (BACnet Virtual Link Layer - 4 Bytes)           │
 │  [ Type: 0x81 ] [ Function: 1B ] [ BVLC Length: 2B ]        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Function 0x0A: Original-Unicast-NPDU
 ┌─────────────────────────────────────────────────────────────┐
 │ NPDU (Network Protocol Data Unit - Version 1)               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ BACnet APDU (Application Protocol Data Unit)                │
 │  [ PDU Type: 1B ] [ Service Choice: 1B ]                    │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Read Operations       ▼ Write Operations      ▼ Device Control
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Service 12:  │        │ Service 15:  │        │ Service 00:  │
 │ ReadProperty │        │ WriteProperty│        │ I-Am         │
 │ (Telemetry)  │        │ (Setpoint)   │        │ Service 17:  │
 └──────────────┘        └──────┬───────┘        │ DeviceCommOff│
                                │                └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Violation Evaluated
                                            ▼
               [ Environmental Sabotage Overrides Purged ]
```

---

## 2. Preventing Physical Facility Sabotage

* **Service 15 (`WriteProperty`):** Traps unauthorized setpoint changes (e.g., forcing datacenter cooling units to maximum temperature or disabling laboratory exhaust scrubbers).
* **Service 17 (`DeviceCommunicationControl`):** Detects attempts to silence building automation controllers prior to physical intrusions.
```

