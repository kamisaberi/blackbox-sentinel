#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <mutex>
#include <thread>
#include <atomic>

namespace sentinel::licensing {

enum class LicenseTier {
    COMMUNITY_FREE,
    ENTERPRISE_IT,
    CRITICAL_INFRASTRUCTURE_OT,
    SOVEREIGN_DEFENSE
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

    // Local Verification & Inspection
    bool load_and_verify(const std::string& license_file_path = "/etc/sentinel/license.lic");
    bool is_module_authorized(const std::string& module_name) const;
    bool is_plugin_authorized(const std::string& plugin_filename) const;

    LicenseTier get_active_tier() const;
    std::string get_tier_name() const;
    const LicenseClaims& get_claims() const { return claims_; }
    static std::string generate_hardware_token();

    // Cloud Backend API Operations
    bool fetch_public_key_online(const std::string& backend_url = "http://127.0.0.1:8000/api/v1");
    bool activate_online(const std::string& backend_url, const std::string& token_or_key, const std::string& hostname = "sentinel-edge");
    bool subscribe_online(const std::string& backend_url, const std::string& plan_slug, const std::string& hostname = "sentinel-edge");
    bool check_revocation_online(const std::string& backend_url, const std::string& token_or_key);

    // Starts background 24-hour lease renewal loop
    void start_lease_renewal_worker(const std::string& backend_url, const std::string& auth_header);
    void stop_lease_renewal_worker();

private:
    LicenseManager();

    bool verify_ed25519_signature(const std::string& payload_b64, const std::string& b64_sig);
    static std::string probe_local_hardware_uuid();

    mutable std::mutex mutex_;
    LicenseClaims claims_;
    bool license_valid_{false};
    std::vector<uint8_t> active_public_key_; // 32-byte Ed25519 public key

    // Auto-renewal thread
    std::atomic<bool> renewal_running_{false};
    std::jthread renewal_thread_;
};

} // namespace sentinel::licensing