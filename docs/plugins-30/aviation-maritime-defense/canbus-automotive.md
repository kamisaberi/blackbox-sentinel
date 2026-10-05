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

