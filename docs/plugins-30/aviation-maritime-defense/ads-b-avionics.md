---

### File: `blackbox-sentinel/docs/plugins-30/aviation-maritime-defense/ads-b-avionics.md`

```markdown
# ADS-B Avionics Surveillance Dissector (`libsentinel_plugin_adsb.so`)

The ADS-B dissector analyzes air traffic surveillance data feeds (1090 MHz Mode S Extended Squitter framed over Ethernet via **Eurocontrol ASTERIX Category 021** or SBS-1/BaseStation TCP port **30003**). It validates ICAO 24-bit aircraft transponder addresses, squawk codes, barometric altitudes, and flight paths.

---

## 1. ASTERIX Cat 021 Message Parsing

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ ASTERIX Cat 021 Header: [ Category: 0x15 (21) ] [ Len: 2B ] │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Field Specification (FSPEC)
 ┌─────────────────────────────────────────────────────────────┐
 │ Decoded Flight Trajectory:                                  │
 │  • ICAO 24-bit Aircraft Address (e.g., 0x3C65B4)            │
 │  • Mode 3/A Squawk Code (e.g., 7700 Emergency, 7500 Hijack) │
 │  • Airspeed & Mach Vector                                   │
 │  • Geometric vs. Barometric Altitude Delta                  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Transponder Spoofing                          ▼ Ghost Aircraft Injection
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Flags Unknown ICAO Hex      │         │ Flags Aircraft Appearing at │
 │ Codes Not in Civil Registry │         │ Mach 3 without Flight Plan  │
 └──────────────┬──────────────┘         └──────────────┬──────────────┘
                │                                       │
                └───────────────────┬───────────────────┘
                                    │ Violation Logged
                                    ▼
       [ Injected Aircraft Discarded before Air Traffic Console ]
```

---

## 2. Trapping TCAS False Alarm Injections

Adversaries inject synthetic ADS-B messages near real commercial flight paths to induce false Traffic Collision Avoidance System (TCAS) **Resolution Advisories (RA)**, forcing aircraft into emergency dives. 

`libsentinel_plugin_adsb.so` cross-references velocity vectors against ground radar returns, dropping synthetic collision vectors at the network perimeter.
```

