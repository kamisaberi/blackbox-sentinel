---

### File: `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/ais-maritime.md`

```markdown
# AIS Maritime Vessel Tracking Dissector (`libsentinel_plugin_ais.so`)

The AIS (Automatic Identification System) dissector inspects maritime navigation and transponder streams encapsulated over UDP port **4001** (or serial NMEA `!AIVDM` sentences). It validates Maritime Mobile Service Identity (MMSI) numbers, navigational status, and positional kinematics to prevent vessel spoofing, dark-fleet ghost ship injections, and false collision-alert manipulation.

---

## 1. AIS Sentence Deconstruction

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Encapsulated AIS Sentence: !AIVDM,1,1,,A,13u?etPv2;0n:O2qE...│
 └──────────────────────────────┬──────────────────────────────┘
                                │ 6-Bit ASCII to Binary Bitstream
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Decoded AIS Message (e.g. Type 1/2/3: Position Report)      │
 │  • Message Type: 6 bits                                     │
 │  • Repeat Indicator: 2 bits                                 │
 │  • MMSI (Vessel ID): 30 bits                                │
 │  • Navigation Status: 4 bits (Under way, At anchor, etc.)   │
 │  • Rate of Turn (ROT) & Speed Over Ground (SOG): 10 bits    │
 │  • Longitude: 28 bits | Latitude: 27 bits                   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ MMSI Whitelist Check                          ▼ Kinematic Plausibility
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Identifies Spoofed MID /    │         │ Traps Impossible Velocity   │
 │ Out-of-Range Country Codes  │         │ (> 40 Knots for Bulk Cargo) │
 └──────────────┬──────────────┘         └──────────────┬──────────────┘
                │                                       │
                └───────────────────┬───────────────────┘
                                    │ Threat Confirmed
                                    ▼
       [ Drops Injected Ghost Ship Frames before Port ECDIS Display ]
```

---

## 2. Detecting Ghost Fleet GPS Spoofing

Adversaries create virtual "ghost fleets" in contested waterways by injecting hundreds of synthetic AIS position reports. The dissector checks the rate-of-turn and speed against the vessel type declared in static data (Message 5), discarding physically impossible maneuvers before records reach electronic chart displays (ECDIS).
```

