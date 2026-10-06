# In-Process License Validation Engine (`LicenseManager.hpp`)

`LicenseManager` executes during daemon initialization, parsing `/etc/sentinel/license.lic`, verifying cryptographic signatures, evaluating hardware bindings, and unlocking entitled subsystems.

---

## 1. Class Synopsis (`LicenseManager.hpp`)

```cpp
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace sentinel::licensing {

enum class LicenseTier : uint8_t {
    COMMUNITY_FREE = 0,
    ENTERPRISE_OT = 1,
    MISSION_CRITICAL_DEFENSE = 2
};

struct LicenseClaims {
    std::string tenant_id;
    std::string licensed_to;
    LicenseTier tier{LicenseTier::COMMUNITY_FREE};
    uint64_t valid_until_epoch_sec{0};
    uint32_t enabled_subsystems_bitmask{0};
    uint32_t enabled_dissectors_bitmask{0};
    std::string locked_hardware_digest;
};

class LicenseManager {
public:
    static LicenseManager& instance() noexcept;

    // Evaluates license on startup
    bool load_and_verify(const std::filesystem::path& license_path);

    // Dynamic Entitlement Checks
    [[nodiscard]] bool is_subsystem_entitled(uint32_t subsystem_id) const noexcept;
    [[nodiscard]] bool is_dissector_entitled(uint32_t dissector_id) const noexcept;
    [[nodiscard]] LicenseTier active_tier() const noexcept;
    [[nodiscard]] const LicenseClaims& claims() const noexcept;

    // Generates platform token for offline licensing request
    [[nodiscard]] std::string generate_hardware_token() const;

private:
    LicenseManager();
    LicenseClaims active_claims_{};
    bool is_verified_{false};

    bool verify_signature(std::string_view payload, std::string_view signature_hex) const;
    bool verify_hardware_binding(const std::string& expected_digest) const;
};

} // namespace sentinel::licensing
```

---

## 2. In-Process Subsystem Gatekeeping

Before `ApplianceCore` initializes any of the 26 subsystems, it queries `LicenseManager`:

```cpp
void ApplianceCore::initialize_subsystems() {
    auto& lic = sentinel::licensing::LicenseManager::instance();

    for (auto& subsystem : registered_subsystems_) {
        uint32_t id = subsystem->subsystem_id();
        
        if (lic.is_subsystem_entitled(id)) {
            subsystem->configure(get_config_for(id));
            subsystem->start();
            XINFER_LOG_INFO("Subsystem {:02d} ({}) Activated.", id, subsystem->name());
        } else {
            XINFER_LOG_WARN("Subsystem {:02d} ({}) SKIPPED: License unentitled.", id, subsystem->name());
        }
    }
}
```

