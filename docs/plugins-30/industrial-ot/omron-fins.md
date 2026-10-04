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

