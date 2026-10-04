---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/hart-ip.md`

```markdown
# HART-IP Industrial Wireless Dissector (`libsentinel_plugin_hart.so`)

The HART-IP dissector monitors process automation networks, chemical refineries, and smart wireless instrumentation communicating over TCP/UDP port **5094**. It decodes HART-IP protocol framing, token-passing PDU structures, and commands to detect transmitter calibration tampering.

---

## 1. Frame Structure & Dissection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ HART-IP Header (Version 1, Message Type, Message ID, Status)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ HART Token-Passing Protocol Data Unit (PDU)                 │
 │  [ Delimiter: 1B ] [ Address: 5B ] [ Command: 1B ]          │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Operational Polling                           ▼ Calibration Overwrite
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Command 01: Read Primary Var│         │ Command 42: Perform Reset   │
 │ Command 03: Read All Vars   │         │ Command 45: Trim DAC Zero   │
 └─────────────────────────────┘         └──────────────┬──────────────┘
                                                        │
                                                        ▼
                            [ Malicious Sensor Desensitization Blocked ]
```

---

## 2. Detecting Physical Sensor Spoofing

Adversaries targeting chemical plants often issue **HART Command 45 (Trim DAC Zero)** or **Command 46 (Trim DAC Gain)** to alter pressure and temperature sensor calibrations, making dangerous pressure buildups appear normal to plant operators. The dissector traps and drops unauthorized Command 45/46 requests at the perimeter.
```

---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/mitsubishi-melsec.md`

```markdown
# Mitsubishi MELSEC Protocol Dissector (`libsentinel_plugin_melsec.so`)

The Mitsubishi MELSEC dissector inspects communications targeting **Mitsubishi Electric iQ-R, Q, and FX Series PLCs** using the MC Protocol (3E/4E frame variants) on TCP port **5007 / 5006**. It verifies batch memory reads, bit/word device writes, and remote CPU execution commands.

---

## 1. MC Protocol Frame Inspection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ MC Protocol 3E Subheader (0x5000: Request / 0xD000: Response)│
 │ [ Network No: 1B ] [ PC No: 1B ] [ Module I/O: 2B ]         │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Command & Subcommand Parsing                                │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Batch Read (0x0401)   ▼ Batch Write (0x1401)  ▼ Remote CPU Control
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Inspect D/M  │        │ Word Write:  │        │ Command 0x1001│
 │ Device Read  │        │ Target: D1000│        │ Remote STOP  │
 │ (Passive)    │        │ (Tampering)  │        │ (CRITICAL)   │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Threat Trapped
                                            ▼
           [ Attacker IP Dropped in Kernel Space in < 0.84 µs ]
```

---

## 2. Invariants & Speed

* **Protected Registers:** Enforces write barriers over critical MELSEC file registers (`R`, `ZR`) and internal relays (`M`).
* **Dissection SLA:** Evaluates MC Protocol frames in **$< 0.48\,\mu\text{s}$**.
```

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

