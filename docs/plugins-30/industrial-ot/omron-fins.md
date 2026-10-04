---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/omron-fins.md`

```markdown
# Omron FINS Protocol Dissector (`libsentinel_plugin_fins.so`)

The Omron FINS (Factory Interface Network Service) dissector inspects communications across **Omron CP, CJ, and NJ/NX Series automation controllers** communicating over TCP/UDP port **9600**. It parses FINS frames to detect unauthorized memory area writes, CPU execution state changes, and cycle time alterations.

---

## 1. FINS Packet Topology & Dissection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ FINS Header (ICF, RSV, GCT, Destination & Source Nodes)     │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Command Code: [ Main Code: 1B ] [ Sub Code: 1B ]            │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Memory Read (01 01)   ▼ Memory Write (01 02)  ▼ Control Commands
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Area: DM/CIO │        │ Overwrites   │        │ 04 01: Forced│
 │ Register Read│        │ Holding Bits │        │ Set/Reset    │
 │ (Authorized) │        │ (Inspected)  │        │ 04 02: Clear │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Violation Logged
                                            ▼
               [ Forced State Overrides Purged at Wire Speed ]
```

---

## 2. Guarding Packaging & Conveyor Logic

* Traps **FINS Command `04 01` (Forced Set/Reset)** and **Command `04 02` (Forced Set/Reset Clear)**, which bypass standard ladder logic execution and force physical digital output bits on field equipment.
* Enforces memory bounds on Omron DM Area (Data Memory) words, preventing recipe tampering in automated packaging lines.
```

---

### Complete in Part 6
- `blackbox-sentinel/docs/plugins-30/plugin-architecture.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/modbus-tcp.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/dnp3-substation.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/siemens-s7comm.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/profinet-rt.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/ethernet-ip-cip.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/hart-ip.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/mitsubishi-melsec.md`
- `blackbox-sentinel/docs/plugins-30/industrial-ot/omron-fins.md`

All 8 Industrial OT & Manufacturing dissectors are now documented.

---

### Files to be Generated in Part 7

The next phase covers the **Energy, Power Grid & Smart Building Plugins** (`plugins-30/energy-utilities/` - 8 files):

1. `plugins-30/energy-utilities/iec-60870-5-104.md` (`libiec104_dissector`: High-voltage grid telecontrol APDU guard)
2. `plugins-30/energy-utilities/iec-61850-goose.md` (`libiec61850_goose`: Substation protection relay multicast guard)
3. `plugins-30/energy-utilities/iec-61850-mms.md` (`libiec61850_mms`: Client-server SCADA telecontrol parser)
4. `plugins-30/energy-utilities/opc-ua-binary.md` (`libopc_ua_dissector`: Industry 4.0 binary communication filter)
5. `plugins-30/energy-utilities/bacnet-ip.md` (`libbacnet_building`: Commercial HVAC & facility automation guard)
6. `plugins-30/energy-utilities/modbus-rtu-serial.md` (`libmodbus_rtu_serial`: RS-485 legacy serial fieldbus inspector)
7. `plugins-30/energy-utilities/enip-cip.md` (`libenip_cip`: Industrial robotics & assembly line protocol guard)
8. `plugins-30/energy-utilities/foundation-fieldbus.md` (`libfieldbus_h1`: Chemical & process instrumentation filter)

Confirm when you are ready to proceed with Part 7.