#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <mutex>

namespace sentinel::licensing {

enum class LicenseTier {
    COMMUNITY_FREE,              // Unlicensed / Default (5 basic IT modules)
    ENTERPRISE_IT,               // Corporate IT & Cloud (WAF, EDR, CWPP, ITDR, Bot)
    CRITICAL_INFRASTRUCTURE_OT,  // Full OT / SCADA (All 26 Subsystems + 30 Plugins)
    SOVEREIGN_DEFENSE            // Full OT + Custom Military Plugins + Classified Support
};

struct LicenseClaims {
    std::string license_id{""};
    std::string customer_name{"Community User"};
    LicenseTier tier{LicenseTier::COMMUNITY_FREE};
    uint64_t issued_at_sec{0};
    uint64_t expires_at_sec{0};
    uint32_t max_nodes{1};
    std::string locked_hardware_uuid{""};
    std::unordered_set<std::string> authorized_modules;
    std::unordered_set<std::string> authorized_plugins;
};

class LicenseManager {
public:
    static LicenseManager& instance() {
        static LicenseManager inst;
        return inst;
    }

    // Loads and verifies license from /etc/sentinel/license.lic using embedded Ed25519 public key
    bool load_and_verify(const std::string& license_file_path = "/etc/sentinel/license.lic");

    // Authorization gates
    bool is_module_authorized(const std::string& module_name) const;
    bool is_plugin_authorized(const std::string& plugin_filename) const;

    LicenseTier get_active_tier() const;
    std::string get_tier_name() const;
    const LicenseClaims& get_claims() const { return claims_; }

    // Probes hardware silicon (TPM / DMI) and outputs base64 machine token
    static std::string generate_hardware_token();

private:
    LicenseManager();

    bool verify_ed25519_signature(const std::string& canonical_json, const std::string& b64_sig);
    static std::string probe_local_hardware_uuid();

    mutable std::mutex mutex_;
    LicenseClaims claims_;
    bool license_valid_{false};
};

} // namespace sentinel::licensing