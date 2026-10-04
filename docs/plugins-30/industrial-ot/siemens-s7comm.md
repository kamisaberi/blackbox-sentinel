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

