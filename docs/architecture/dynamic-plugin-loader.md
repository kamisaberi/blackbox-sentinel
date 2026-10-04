---

### File: `blackbox-sentinel/docs/architecture/dynamic-plugin-loader.md`

```markdown
# Dynamic Dissector Plugin Architecture & Symbol Isolation

The 30 industrial protocol dissector plugins (e.g., Modbus, Siemens S7Comm, DICOM, MAVLink) are compiled as modular shared libraries (`libsentinel_plugin_*.so`) and loaded dynamically at runtime via `dlopen`.

---

## 1. Symbol Encapsulation via `RTLD_LAZY | RTLD_LOCAL`

To prevent conflicting third-party symbols or cross-dissector symbol contamination, plugins are loaded with strict local visibility:

```cpp
#include <dlfcn.h>
#include <stdexcept>
#include <string>

void* load_dissector_plugin(const std::string& path) {
    ::dlerror(); // Clear error buffer

    // RTLD_LAZY : Resolve unresolved symbols as instructions execute
    // RTLD_LOCAL: Symbols defined inside this plugin are NOT visible to other plugins
    void* handle = ::dlopen(path.c_str(), RTLD_LAZY | RTLD_LOCAL);
    
    if (!handle) {
        throw std::runtime_error("Plugin load failed: " + std::string(::dlerror()));
    }
    return handle;
}
```

---

## 2. Dissector ABI Contract (`<sentinel/dissector_interface.hpp>`)

Each dissector plugin implements a pure virtual interface and exports standard factory symbols:

```cpp
#pragma once

#include <span>
#include <string_view>
#include <cstdint>

namespace sentinel {

struct DissectionResult {
    bool is_protocol_match{false};
    bool is_anomaly_detected{false};
    uint32_t rule_id{0};
    std::string_view description{};
    std::span<const float> extracted_features{};
};

class IDissectorPlugin {
public:
    virtual ~IDissectorPlugin() = default;

    [[nodiscard]] virtual std::string_view protocol_name() const noexcept = 0;
    [[nodiscard]] virtual uint16_t default_port() const noexcept = 0;

    // Zero-allocation packet dissection pass
    virtual DissectionResult dissect_packet(
        std::span<const uint8_t> payload, 
        uint64_t timestamp_ns
    ) = 0;
};

} // namespace sentinel

// Unmangled C factory export signatures
extern "C" {
    sentinel::IDissectorPlugin* create_dissector();
    void destroy_dissector(sentinel::IDissectorPlugin* plugin);
    const char* get_dissector_abi_version();
}
```

---

## 3. ABI Handshake Verification

Before activating a protocol plugin, `blackbox-sentinel` queries `get_dissector_abi_version()`. If the ABI version does not match `SENTINEL_DISSECTOR_ABI_V1`, the plugin is rejected immediately to prevent memory corruption.
```

