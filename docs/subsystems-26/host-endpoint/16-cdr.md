---

### File: `blackbox-sentinel/docs/subsystems-26/host-endpoint/16-cdr.md`

```markdown
# Subsystem 16: Content Disarm & Reconstruction (`16_cdr`)

`16_cdr` neutralizes weaponized documents (PDFs, Office OOXML, RTF) transferred over network streams (HTTP, SMB, DICOM) by parsing document structures in memory and stripping executable components without writing untrusted payloads to disk.

---

## 1. Disarm & Rebuild Pipeline

```text
 [ Ingress Inbound Document (e.g. Invoice.pdf / Specs.docx) ]
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Zero-Copy File Structure Parser                             │
 │   - Deconstructs DOM / OLE2 streams / PDF XREF tables       │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼ Recursive Macro & Script Stripper
 ┌─────────────────────────────────────────────────────────────┐
 │ Component Removal:                                          │
 │  • Strips VBA Macros, ActiveX Controls, and DDE formulas    │
 │  • Neutralizes PDF /JavaScript, /Launch, and /EmbeddedFiles │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ In-Memory Reconstruction Engine                             │
 │   - Emits pure visual representation (Sanitized Document)   │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
 [ Safe Stream Forwarded to Recipient (Zero Exploit Payload) ]
```

---

## 2. Invariants & Speed

* **Zero Disk Footprint:** Documents are disassembled and rebuilt entirely in pre-allocated RAM scratchpads, preventing temporary-file race conditions.
* **Latency Profile:** Sanitizes a $2\text{ MB}$ PDF in **$< 8.5\,\text{ms}$**.
```

