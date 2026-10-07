#pragma once
#include <string>
#include <cstdint>
#include <chrono>

namespace sentinel::core {

enum class HardwareSecurityTier {
    PHYSICAL_TPM2,
    VIRTUAL_TPM,
    DMI_SOFTWARE_FALLBACK
};

struct HardwareProfile {
    HardwareSecurityTier tier;
    std::string machine_uuid;
    std::string system_vendor;
    std::string board_serial;
    std::string kernel_release;
    std::string tpm_fingerprint;
    uint64_t probed_at_sec;
};

class ZtpTokenAgent {
public:
    static ZtpTokenAgent& instance() {
        static ZtpTokenAgent inst;
        return inst;
    }

    // Probes physical and virtual registers, generating a complete profile
    HardwareProfile probe_hardware_profile();

    // Generates a base64-encoded, portable cryptographic enrollment token (ZTP-...)
    std::string generate_provisioning_token(const std::string& tenant_hint = "default");

    // Validates if a token matches the physical machine executing it
    bool verify_token_locally(const std::string& ztp_token);

private:
    ZtpTokenAgent() = default;

    static std::string read_sysfs_string(const std::string& path);
    static std::string compute_sha256_hex(const std::string& input);
    static std::string base64_encode(const std::string& input);
    static std::string base64_decode(const std::string& input);
};

} // namespace sentinel::core