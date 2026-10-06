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

