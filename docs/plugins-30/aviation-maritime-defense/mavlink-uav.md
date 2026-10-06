# MAVLink Autonomous UAV Protocol Dissector (`libsentinel_plugin_mavlink.so`)

The MAVLink dissector inspects micro air vehicle telemetry and autonomous drone datalinks operating over UDP/TCP ports **14550, 14551, and 5760**. It validates **MAVLink v1 (`0xFE`) and v2 (`0xFD`)** framing, detecting GPS spoofing, unauthorized flight mode overrides, and waypoint injection attacks.

---

## 1. Frame Structure & Dissection Pipeline

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ MAVLink v2 Frame (Header: 10 Bytes, Magic Byte 0xFD)        │
 │  [ Length: 1B ] [ Incompat/Compat Flags: 2B ] [ Seq: 1B ]   │
 │  [ System ID: 1B ] [ Component ID: 1B ] [ Message ID: 3B ] │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Message ID Demultiplexing                                   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Msg 0: HEARTBEAT      ▼ Msg 33: GLOBAL_POS    ▼ Msg 76: COMMAND_LONG
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Autopilot    │        │ Lat/Lon/Alt  │        │ Flight Mode  │
 │ Type & Status│        │ Kinematics   │        │ Override     │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                ▼ Kinematic Check       ▼ Command Authorization
 ┌──────────────────────────────────────────────┐┌──────────────────────────────┐
 │ Traps Impossible Acceleration & GPS Jumps    ││ Traps Unauthorized RTL/Disarm│
 └──────────────────────────────────────────────┘└──────────────────────────────┘
```

---

## 2. In-Memory GPS Spoofing Detection

`libsentinel_plugin_mavlink.so` calculates physical delta velocity between successive `GLOBAL_POSITION_INT` messages:

$$v_{\text{calc}} = \frac{\Delta \text{Distance}}{\Delta t}$$

If calculated horizontal velocity exceeds the drone's aerodynamic envelope ($v > 45\,\text{m/s}$ for quadcopters) or vertical acceleration violates physical gravity bounds, GPS spoofing is confirmed. The dissector commands Tier 2 `libblackbox` to block the attacking ground control station (GCS) telemetry link in $< 0.84\,\mu\text{s}$.

