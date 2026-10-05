---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/iec-61850-mms.md`

```markdown
# IEC 61850 MMS Telecontrol Dissector (`libsentinel_plugin_mms.so`)

The IEC 61850 MMS (Manufacturing Message Specification) dissector monitors client-server SCADA and Human-Machine Interface (HMI) traffic communicated over TCP port **102**. It parses ISO-COTP and Abstract Syntax Notation One (ASN.1) BER streams to validate remote telemetry reads, setting changes, and logical node writes.

---

## 1. Protocol Encapsulation Hierarchy

```text
 [ TCP Port 102 Stream ] ──► [ TPKT (RFC 1006) ] ──► [ ISO-COTP (ISO 8073) ]
                                                            │
                                                            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ OSI Presentation & Session Layer Layering                    │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ MMS PDU (Manufacturing Message Specification - ISO 9506)    │
 │  [ confirmed-RequestPDU ] [ confirmed-ResponsePDU ]         │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Read Request          ▼ Write Request         ▼ File Services
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ getNameList  │        │ writeVariable│        │ fileOpen /   │
 │ readVariable │        │ (Relay Trips │        │ fileDelete   │
 │ (Authorized) │        │  & Setpoints)│        │ (Tampering)  │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Violation Logged
                                            ▼
               [ Out-of-Spec Substation Changes Blocked ]
```

---

## 2. Invariants & Speed

* **Zero Memory Leak Parsing:** Uses a non-recursive ASN.1 parser operating on stack memory, preventing memory exhaustion when parsing deeply nested BER structures.
* **Latency Profile:** $< 1.1\,\mu\text{s}$ per MMS confirmed request frame.
```

