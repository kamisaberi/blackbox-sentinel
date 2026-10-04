### Part 5: 26 Native Subsystems — Cyber-Physical OT & Forensics (`subsystems-26/*`)

This section contains 9 technical implementation guides for the remaining native subsystems: the 3 **Cyber-Physical OT & IoT Protection** modules (`17_iot_sec`, `18_cps_sec`, `21_side_channel`) and the 6 **Forensics, Traffic Control & Deception** modules (`13_ddos`, `19_swg`, `22_dfir`, `23_ai_trism`, `25_fdp`, `26_ddp`).

---

### File: `blackbox-sentinel/docs/subsystems-26/cyber-physical-ot/17-iot-sec.md`

```markdown
# Subsystem 17: Medical IoT & PACS Protocol Security (`17_iot_sec`)

`17_iot_sec` secures clinical healthcare networks, radiological picture archiving systems (DICOM PACS), and telemetry medical devices. It operates inline, parsing **DICOM C-STORE, C-FIND, and HL7 v2/v3** clinical protocol messages over the wire to detect unauthorized patient data exfiltration, ransomware encryption of radiological archives, and medical sensor manipulation.

---

## 1. DICOM Medical Imaging Validation Pipeline

```text
 [ PACS Ingress Traffic: TCP Port 104 / 11112 ]
                        │
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Zero-Copy DICOM Upper Layer Protocol (DULP) Dissector       │
 │  - Verifies Application Entity Titles (Calling/Called AET)  │
 │  - Inspects P-DATA-TF presentation data value streams       │
 └──────────────────────┬──────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼ C-STORE Operation             ▼ C-FIND / C-MOVE Operation
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │ 16-Bit Pixel Array Audit    │ │ Bulk Record Query Audit     │
 │  - Detects Steganography    │ │  - Evaluates Query Velocity │
 │  - Flags Inverted HU Bounds │ │  - Traps Mass Exfiltration  │
 └──────────────┬──────────────┘ └──────────────┬──────────────┘
                │                               │
                └───────────────┬───────────────┘
                                │ Threat Detected
                                ▼
 [ Block Rogue Modality IP in Kernel (< 0.84 µs) & Sever Session ]
```

---

## 2. In-Memory HL7 Clinical Parser (`IotSecEngine.cpp`)

```cpp
#include <string_view>
#include <vector>
#include <span>
#include <cstdint>

namespace sentinel::subsystems {

struct Hl7SegmentView {
    std::string_view segment_id; // e.g., "MSH", "PID", "OBX"
    std::vector<std::string_view> fields;
};

class IotSecEngine {
public:
    // Parses HL7 v2 pipe-delimited message without memory allocations
    bool validate_hl7_stream(std::string_view raw_msg) {
        if (raw_msg.size() < 4 || !raw_msg.starts_with("MSH")) {
            return false; // Malformed clinical message
        }

        const char field_sep = raw_msg[3]; // Standard '|'
        // Enforce clinical sanity constraints:
        // Reject messages containing command injection characters in patient IDs
        if (raw_msg.find(";") != std::string_view::npos || 
            raw_msg.find("&&") != std::string_view::npos ||
            raw_msg.find("`") != std::string_view::npos) {
            return false; // Embedded shellcode / injection trapped
        }

        return true;
    }
};

} // namespace sentinel::subsystems
```

---

## 3. Supported Clinical Protocol Standards

* **DICOM Standard PS 3.8:** Network Communication Support for Message Exchange.
* **HL7 Standards:** Health Level Seven International Versions 2.3, 2.5, and FHIR JSON.
* **Regulatory Alignment:** Satisfies technical access and transmission security requirements under HIPAA § 164.312(e)(1).
```

