---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/modbus-rtu-serial.md`

```markdown
# Modbus RTU Serial-over-IP Dissector (`libsentinel_plugin_modbus_rtu.so`)

The Modbus RTU Serial dissector inspects legacy serial fieldbus traffic encapsulated over TCP/UDP network streams (e.g., Moxa NPort, Advantech, or Digi serial terminal servers) on user-defined ports (commonly **4001, 4101, or 502**).

---

## 1. RTU vs. TCP Framing

Unlike Modbus TCP, Modbus RTU does not feature an MBAP header; frames rely on a trailing **CRC-16** check and silent inter-character gaps:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Modbus RTU Frame Encapsulated over TCP/UDP Stream           │
 │  [ Slave Address: 1B ] [ Function Code: 1B ]                │
 │  [ Data Payload: N Bytes ] [ CRC-16 Checksum: 2B (Little-End)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ AVX2 Vectorized CRC-16 Engine                               │
 │   - Polynomial: 0xA001 (CRC-16-IBM)                         │
 │   - Validates Frame Integrity in < 80 nanoseconds           │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ CRC Verified
 [ Function Code & Coil Bounds Evaluated Against SCADA Policy ]
```

---

## 2. CRC-16 Hardware Verification

The plugin uses an AVX2-accelerated lookup table to calculate and verify the Modbus RTU CRC-16 checksum, dropping corrupted, injected, or truncated frames before passing the stream to field serial transceivers.
```

