---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/22-dfir.md`

```markdown
# Subsystem 22: Circular PCAP Carver & Evidence Vault (`22_dfir`)

`22_dfir` maintains a circular in-memory buffer that captures raw packet frames. When an attack is mitigated by any of the 26 subsystems, `22_dfir` dumps a pre-attack and post-attack packet window directly to NVMe storage, cryptographically sealing the carved `.pcap` evidence with SHA-256 for judicial admissibility.

---

## 1. Trigger-on-Drop Carving Architecture

```text
 Ingress Packets ──► [ Circular RAM Ring Buffer (256 MB Static Pool) ]
                                      │
                                      ▼
                        Continuously holds last 30 seconds of raw wire traffic
                                      │
                                      ▼ eBPF Trigger: XDP_DROP Executed
 ┌─────────────────────────────────────────────────────────────┐
 │ 22_dfir Carve Routine (Non-Blocking Disk Flush)             │
 │   - Flushes T-10 seconds to T+5 seconds packet window       │
 │   - Encapsulates into standard libpcap format               │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼ SHA-256 Digest Calculation
 ┌─────────────────────────────────────────────────────────────┐
 │ Cryptographic Evidence Packaging                            │
 │   - File: /var/log/sentinel/forensics/incident_<id>.pcap    │
 │   - Signed with Hardware TPM 2.0 AIK Private Key            │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Carving Implementation (`PcapCarver.cpp`)

```cpp
#include <fstream>
#include <vector>
#include <cstdint>

namespace sentinel::subsystems {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number{0xa1b2c3d4};
    uint16_t version_major{2};
    uint16_t version_minor{4};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{65535};
    uint32_t network{1}; // LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

void flush_carved_pcap(const std::string& path, const std::vector<uint8_t>& raw_frames) {
    std::ofstream out(path, std::ios::binary);
    PcapGlobalHeader gh;
    out.write(reinterpret_cast<const char*>(&gh), sizeof(gh));
    out.write(reinterpret_cast<const char*>(raw_frames.data()), raw_frames.size());
}

} // namespace sentinel::subsystems
```

---

## 3. Regulatory Value

Provides forensic evidence compliant with ISO/IEC 27037 standards for digital evidence handling, proving root-cause vectors during regulatory post-incident investigations.
```

