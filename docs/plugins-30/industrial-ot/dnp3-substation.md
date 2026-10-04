---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/dnp3-substation.md`

```markdown
# DNP3 Electric Substation Dissector (`libsentinel_plugin_dnp3.so`)

The DNP3 (Distributed Network Protocol) dissector inspects electric utility telecontrol and SCADA traffic on TCP/UDP port **20000**. It parses Data Link, Transport, and Application layers to detect unauthorized **Select-Before-Operate (SBO)** relay tripping, class poll anomalies, and outstation address spoofing.

---

## 1. Protocol Layer Deconstruction

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Data Link Layer: [ Start 0x0564: 2B ] [ Len: 1B ] [ Ctrl: 1B]│
 │                  [ Destination: 2B ] [ Source: 2B ] [ CRC: 2B]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Application Layer: [ App Control: 1B ] [ Function Code: 1B ]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Polling Operations    ▼ Direct Operate        ▼ Select-Before-Operate
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ FC 01: Read  │        │ FC 05: Direct│        │ FC 03: Select│
 │ Classes 0/1/2│        │ Operate (Risk│        │ FC 04: Operate│
 │ (Telemetry)  │        │ High)        │        │ (Substation) │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Check Outstation Whitelist
                                            ▼
               [ Detects Unauthorized Breaker Opening Commands ]
```

---

## 2. Invariant Enforcement & Threat Signatures

* **Direct Operate Suppression:** Industrial electrical safety standards mandate the use of `Select-Before-Operate` (FC `03` followed by FC `04`) before tripping high-voltage switchgear. Issuing unexpected `Direct Operate No Ack` (FC `06`) commands indicates automated grid sabotages (e.g., **Industroyer2**) and triggers an immediate in-kernel block.
* **CRC Validation:** Evaluates the DNP3 Data Link CRC-16 polynomial ($X^{16} + X^{13} + X^8 + 1$) in hardware via AVX2 instructions.
```

---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/siemens-s7comm.md`

```markdown
# Siemens S7Comm Dissector Plugin (`libsentinel_plugin_s7comm.so`)

The Siemens S7Comm dissector inspects industrial communications targeting **Siemens S7-300, S7-400, S7-1200, and S7-1500 PLCs** on TCP port **102**. It decodes TPKT, COTP, and S7 Protocol Data Units, intercepting PLC stop commands, memory block tampering (DB/M blocks), and unauthorized firmware flashing.

---

## 1. Frame Encapsulation Architecture

```text
 [ TCP Port 102 Stream ]
           │
           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ TPKT Header (RFC 1006 - 4 Bytes: Version 3, Reserved, Length)│
 └─────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ COTP Header (ISO 8073 - Connection-Oriented Transport Prot)  │
 └─────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ S7Comm Header (Protocol ID 0x32, ROSCTR: Job, Ack, UserData) │
 └─────────────────────────────┬───────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼ PLC Control Commands ▼ Data Block Mutations ▼ Diagnostics
 ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
 │ Stop PLC     │       │ Write Var:   │       │ Read SZL /   │
 │ (0x29)       │       │ DB1.DBB0     │       │ Request Diag │
 │ (CRITICAL)   │       │ (Tampering)  │       │ (Recon)      │
 └──────┬───────┘       └──────┬───────┘       └──────────────┘
        │                      │
        └──────────┬───────────┘
                   │ Attack Identified
                   ▼
 [ Source IP Blocked in Kernel (< 0.84 µs) -> PLC Shielded ]
```

---

## 2. Detecting Stuxnet-Style Memory Manipulations

Stuxnet modified specific organization blocks (e.g., `OB35`) and data blocks (`DB890`) governing centrifuge drive frequencies:
* `libs7comm_dissector` parses the S7 parameter block for **Function `0x05` (Write Variable)**.
* It compares the addressed Data Block (`DB`) number against a local whitelist.
* Any attempt to issue `0x29` (PLC Stop) or overwrite safety-critical DB blocks triggers an immediate `XDP_DROP` mitigation rule, keeping the PLC operational.
```

---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/profinet-rt.md`

```markdown
# PROFINET Real-Time Dissector (`libsentinel_plugin_profinet.so`)

The PROFINET RT dissector analyzes high-speed industrial Ethernet automation frames operating over **EtherType `0x8892`**. It inspects Real-Time (RT) cyclic process data and Acyclic Discovery and Configuration Protocol (DCP) transactions without adding propagation delay to manufacturing motion-control loops.

---

## 1. PROFINET Frame Categorization

```text
 [ Ethernet Frame (EtherType 0x8892) ]
                  │
                  ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Frame ID Classification                                     │
 └────────────────┬────────────────────────────┬───────────────┘
                  │                            │
                  ▼ (0x8000 - 0xBFFF)          ▼ (0xFEFD - 0xFEFF)
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │ PROFINET Cyclic Real-Time   │ │ PROFINET DCP (Discovery)    │
 │  - Cycle Counter Drift      │ │  - Set IP / Reset to Factory│
 │  - DataStatus / IOXCS State │ │  - Station Name Spoofing    │
 └─────────────────────────────┘ └─────────────┬───────────────┘
                                               │ Malicious Reset Trapped
                                               ▼
                         [ Dropped in Kernel Driver before PLC ]
```

---

## 2. Detecting Rogue DCP Factory Resets

Adversaries often weaponize PROFINET Discovery and Basic Configuration Protocol (DCP) to execute unauthenticated denial-of-service attacks:
* **Service `0x04` (Set Request) / Sub-option `0x05` (Reset to Factory Defaults):** When observed outside an active maintenance window, the packet is purged in driver space, preventing line stoppages across automated manufacturing cells.
```

---

### File: `blackbox-sentinel/docs/plugins-30/industrial-ot/ethernet-ip-cip.md`

```markdown
# EtherNet/IP & CIP Dissector (`libsentinel_plugin_enip.so`)

The EtherNet/IP dissector inspects Rockwell Automation (Allen-Bradley) control networks operating on TCP/UDP port **44818**. It parses encapsulation headers and internal Common Industrial Protocol (CIP) commands, validating tag reads, tag writes, and assembly data integrity.

---

## 1. Common Industrial Protocol (CIP) Inspection

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ EtherNet/IP Encapsulation Header (24 Bytes)                 │
 │  [ Command: 2B ] [ Length: 2B ] [ Session Handle: 4B ]      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Command: SendRRData / SendUnitData
 ┌─────────────────────────────────────────────────────────────┐
 │ Common Industrial Protocol (CIP) Packet                     │
 │  [ Service: 1B ] [ Path Size: 1B ] [ Request Path: N Bytes ]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Service 0x4C │        │ Service 0x4E │        │ Service 0x0E │
 │ Read Tag     │        │ Write Tag    │        │ Get Attribute│
 │ (Authorized) │        │ (Inspected)  │        │ (Telemetry)  │
 └──────────────┘        └──────┬───────┘        └──────────────┘
                                │ Tag: "ESTOP_BYPASS" == 1
                                ▼
         [ Safety Invariant Breach -> Trigger eBPF Drop ]
```

---

## 2. Threat Vector: Unauthorized CIP Tag Writes

Attackers exploit CIP by submitting unauthenticated `Write Tag` (Service `0x4D` / `0x4E`) requests to manipulate safety logic tags (e.g., `EMERGENCY_STOP_BYPASS` or `PRESSURE_RELIEF_OVERRIDE`). 

`libsentinel_plugin_enip.so` parses symbolic CIP paths in memory and drops unauthorized mutations before the Rockwell ControlLogix controller updates its output table.
```

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

