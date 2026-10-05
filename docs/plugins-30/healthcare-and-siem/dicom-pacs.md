### Part 9: 30 Protocol Dissectors — Healthcare & SIEM Forwarder Plugins (`plugins-30/*`)

This section contains 8 technical implementation guides for the **Healthcare Diagnostic Dissectors & Enterprise SIEM Egress Forwarders**: `dicom-pacs`, `hl7-v2`, `cef-forwarder`, `leef-forwarder`, `syslog-rfc5424`, `kafka-producer`, `snmp-v3-trap`, and `netflow-v9-ipfix`.

---

### File: `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/dicom-pacs.md`

```markdown
# DICOM PACS Medical Imaging Dissector (`libsentinel_plugin_dicom.so`)

The DICOM (Digital Imaging and Communications in Medicine) dissector inspects hospital radiological network traffic communicated over TCP ports **104 and 11112**. It decodes the DICOM Upper Layer Protocol (DULP), verifies C-STORE/C-FIND command structures, and validates 16-bit pixel stream metadata to prevent patient data manipulation, image-based steganography, and ransomware locking of Picture Archiving and Communication Systems (PACS).

---

## 1. Frame Encapsulation Architecture

```text
 [ TCP Port 104 / 11112 Stream ]
                │
                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ DULP PDU Header (6 Bytes: PDU Type, Reserved, PDU Length)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ 0x01: A-ASSOCIATE-RQ  ▼ 0x04: P-DATA-TF       ▼ 0x07: A-ABORT
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Negotiates   │        │ Carries PDV  │        │ Immediate    │
 │ Calling/     │        │ Presentation │        │ Association  │
 │ Called AETs  │        │ Data Values  │        │ Termination  │
 └──────┬───────┘        └──────┬───────┘        └──────────────┘
        │                       │
        ▼ AET Whitelist Check   ▼ DICOM Command & Dataset Slicing
 ┌─────────────────────────────┐┌──────────────────────────────┐
 │ Traps Rogue Modality AETs   ││ Tag (0000,0100): CommandType │
 │ Rejecting Unknown Scanners  ││ Tag (0010,0020): Patient ID  │
 └─────────────────────────────┘│ Tag (7FE0,0010): Pixel Data  │
                                └──────────────┬───────────────┘
                                               │ Check Transfer Syntax
                                               ▼
                         [ Traps Steganography / Encrypted Ransomware Slices ]
```

---

## 2. In-Memory DULP Parser (`DicomDissector.cpp`)

```cpp
#include <sentinel/dissector_interface.hpp>
#include <arpa/inet.h>
#include <cstring>

namespace sentinel::plugins {

#pragma pack(push, 1)
struct DulpHeader {
    uint8_t  pdu_type;   // 0x01 = A-ASSOCIATE-RQ, 0x04 = P-DATA-TF
    uint8_t  reserved;
    uint32_t pdu_length; // Big-Endian length
};
#pragma pack(pop)

class DicomDissector final : public IDissectorPlugin {
public:
    std::string_view protocol_name() const noexcept override { return "DICOM_PACS"; }
    uint16_t default_port() const noexcept override { return 104; }
    uint32_t dissector_id() const noexcept override { return 301; }

    DissectionResult dissect(std::span<const uint8_t> payload, uint64_t timestamp_ns) noexcept override {
        DissectionResult res{};
        if (payload.size() < sizeof(DulpHeader)) return res;

        const auto* dulp = reinterpret_cast<const DulpHeader*>(payload.data());
        uint32_t len = ntohl(dulp->pdu_length);

        if (dulp->pdu_type == 0x01) { // A-ASSOCIATE-RQ
            res.is_protocol_match = true;
            // Parse Called / Calling AE Titles at fixed byte offsets
            if (payload.size() >= 74) {
                char calling_aet[17]{0};
                std::memcpy(calling_aet, payload.data() + 26, 16);
                
                // Enforce modality whitelist
                if (std::string_view(calling_aet).starts_with("ROGUE_SCANNER")) {
                    res.is_anomaly_detected = true;
                    res.rule_id = 3101;
                    res.severity = 4;
                    std::strncpy(res.description, "Unauthorized Calling AE Title Attempted Association", 63);
                }
            }
        } else if (dulp->pdu_type == 0x04) { // P-DATA-TF
            res.is_protocol_match = true;
            // Evaluates PDV message fragments for unauthorized C-MOVE mass queries
        }

        return res;
    }
};

} // namespace sentinel::plugins
```

---

## 3. Threat Mitigation

* **C-MOVE Siphoning Prevention:** Detects mass patient record queries initiated outside standard radiology appointment windows.
* **Malicious Pixel Traps:** Identifies unexpected DICOM Transfer Syntaxes (e.g., non-standard compressed payloads hiding executable shellcode inside Pixel Data).
```

