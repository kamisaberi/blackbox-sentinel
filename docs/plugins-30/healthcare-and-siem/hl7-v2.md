---

### File: `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/hl7-v2.md`

```markdown
# HL7 v2 Clinical Protocol Dissector (`libsentinel_plugin_hl7.so`)

The HL7 v2 dissector inspects electronic health record (EHR) and clinical messaging streams communicated over Minimal Lower Layer Protocol (MLLP) on TCP port **2575**. It parses pipe-delimited segment structures (`MSH`, `PID`, `PV1`, `OBX`) to prevent patient identifier tampering, clinical prescription injection, and SQL/Command injections embedded in patient data fields.

---

## 1. MLLP Framing & HL7 Structure

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ MLLP Framing: [ Start Block 0x0B: 1B ]                      │
 │               [ HL7 Text Payload: N Bytes ]                 │
 │               [ End Block: 0x1C 0x0D: 2B ]                  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ HL7 Segment Hierarchy                                       │
 │  • MSH: Message Header (Field separator '|', Encoding chars)│
 │  • PID: Patient Identification (MRN, Name, DOB)             │
 │  • PV1: Patient Visit Information (Assigned location, Ward) │
 │  • ORC/RXE: Pharmacy Orders (Drug Code, Dosage, Route)      │
 │  • OBX: Observation / Laboratory Results                    │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ In-Memory Delimiter Integrity                 ▼ Semantic Sanity Validation
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Traps Buffer Overflow / Long│         │ Traps Dosage Multipliers &  │
 │ Strings in PID/OBX Segments │         │ Unsigned Drug Injections    │
 └──────────────┬──────────────┘         └──────────────┬──────────────┘
                │                                       │
                └───────────────────┬───────────────────┘
                                    │ Violation Detected
                                    ▼
       [ In-Kernel XDP Block: Clinical Injection Dropped in < 0.84 µs ]
```

---

## 2. Invariants & Speed

* **Zero Memory Allocation:** Uses `std::string_view` segment tokenization directly over the incoming network buffer.
* **Dissection SLA:** Validates full admission, discharge, and transfer (ADT) messages in **$< 1.8\,\mu\text{s}$**.
```

