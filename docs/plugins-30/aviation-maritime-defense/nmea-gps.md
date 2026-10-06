# NMEA 0183/2000 GPS Navigation Dissector (`libsentinel_plugin_nmea.so`)

The NMEA dissector monitors marine and aviation GPS/GNSS receiver sentences communicated over UDP/TCP networks (ports **10110, 2000**) or RS-422 serial bridges. It verifies sentence checksums, Horizontal Dilution of Precision (HDOP), and position continuity across `$GPGGA`, `$GPRMC`, and `$GPVTG` sentences.

---

## 1. Sentence Parsing & Validation

```text
 [ Sentence: $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47 ]
                                      │
                                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. Hardware XOR Checksum Verification (Must match 0x47)     │
 │ 2. Satellite Fix Quality Check (0 = Invalid, 1 = GPS Fix)   │
 │ 3. Satellite Tracking Count (Must be >= 4 for 3D Fix)       │
 │ 4. HDOP Validation (Horizontal Dilution of Precision <= 2.0)│
 └────────────────────────────────────┬────────────────────────┘
                                      │
                                      ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Positional Delta Engine                                     │
 │  - Traps instantaneous coordinate teleportation             │
 │  - Flags satellite count drops accompanied by sudden jumps  │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Invariants & Speed

* **SIMD XOR Checksumming:** Validates NMEA ASCII checksums using AVX2 instructions in **$< 40\,\text{ns}$**.
* **Spoofing Alert:** When HDOP reports optimal geometry ($< 1.0$) but satellite constellation counts drop to zero, GPS jamming/spoofing is flagged immediately.

