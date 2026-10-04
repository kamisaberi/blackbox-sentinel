### Part 6: 30 Protocol Dissectors — Architecture & Industrial OT Plugins (`plugins-30/*`)

This section contains 9 technical implementation guides: the core plugin architecture and ABI contract, followed by the 8 **Industrial OT & Manufacturing Dissectors** (`modbus-tcp`, `dnp3-substation`, `siemens-s7comm`, `profinet-rt`, `ethernet-ip-cip`, `hart-ip`, `mitsubishi-melsec`, `omron-fins`).

---

### File: `blackbox-sentinel/docs/plugins-30/plugin-architecture.md`

```markdown
# Protocol Dissector Plugin Architecture & Zero-Allocation ABI

The 30 industrial and enterprise protocol dissectors in `blackbox-sentinel` are implemented as modular, dynamically loaded shared objects (`libsentinel_plugin_*.so`). They parse protocol Application Protocol Data Units (APDUs), extract semantic metrics, and identify command anomalies at wire speed.

---

## 1. Dissector Execution Sequence

```text
 [ Ingress L4 Packet Payload (TCP Stream or UDP Datagram) ]
                           │
                           ▼ std::span<const uint8_t> (Zero-Copy)
 ┌─────────────────────────────────────────────────────────────┐
 │ Protocol Dissector Plugin (e.g. libsentinel_plugin_modbus.so│
 ├─────────────────────────────────────────────────────────────┤
 │ 1. Magic Bytes / Port Verification                         │
 │ 2. In-Place Header Unpacking (#pragma pack structs)         │
 │ 3. Command & Function Code Legality Check                   │
 │ 4. Address Range & Setpoint Boundary Evaluation             │
 └─────────────────────────┬───────────────────────────────────┘
                           │
                           ▼ DissectionResult (Passed by Value)
 ┌─────────────────────────────────────────────────────────────┐
 │ Struct DissectionResult                                     │
 │  • is_protocol_match : true                                 │
 │  • is_anomaly_detected: true (e.g. Illegal PLC Write)       │
 │  • rule_id            : 1801                                │
 │  • extracted_features : std::span<const float, 16>          │
 └─────────────────────────┬───────────────────────────────────┘
                           │
                           ▼ Anomaly Confirmed
 [ In-Kernel eBPF Drop Gate Triggered in < 0.84 µs ]
```

---

## 2. The C++20 Pure Virtual ABI Contract (`IDissectorPlugin.hpp`)

```cpp
#pragma once

#include <span>
#include <string_view>
#include <cstdint>

namespace sentinel::plugins {

#pragma pack(push, 8)
struct DissectionResult {
    bool is_protocol_match{false};
    bool is_anomaly_detected{false};
    uint32_t rule_id{0};
    uint32_t severity{0};
    char description[64]{0};
    uint32_t feature_count{0};
    float features[16]{0.0f}; // Pre-allocated feature array
};
#pragma pack(pop)

class IDissectorPlugin {
public:
    virtual ~IDissectorPlugin() = default;

    [[nodiscard]] virtual std::string_view protocol_name() const noexcept = 0;
    [[nodiscard]] virtual uint16_t default_port() const noexcept = 0;
    [[nodiscard]] virtual uint32_t dissector_id() const noexcept = 0;

    // Fast-path dissection: Guaranteed zero dynamic memory allocations
    virtual DissectionResult dissect(
        std::span<const uint8_t> payload, 
        uint64_t timestamp_ns
    ) noexcept = 0;
};

} // namespace sentinel::plugins

#define SENTINEL_DISSECTOR_ABI_VERSION "1.0.0-cxx20"

extern "C" {
    sentinel::plugins::IDissectorPlugin* create_dissector();
    void destroy_dissector(sentinel::plugins::IDissectorPlugin* plugin);
    const char* get_dissector_abi_version();
}
```

---

## 3. Dissector Safety Invariants

1. **Zero Heap Allocations:** Dissectors must never call `malloc`, `new`, or resize containers. Results are returned using fixed-capacity stack structures (`DissectionResult`).
2. **Bounds Enforcement:** All memory dereferences operate against `std::span` boundaries, preventing buffer over-reads on truncated packets.
3. **Symbol Isolation:** Plugins are loaded using `dlopen(path, RTLD_LAZY | RTLD_LOCAL)`, isolating internal helper routines from other plugins.
```

