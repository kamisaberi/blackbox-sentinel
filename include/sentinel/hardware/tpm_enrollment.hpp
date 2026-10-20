#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace sentinel::hardware
{

    struct HardwareIdentityToken
    {
        bool tpm_attested{false};
        std::string tpm_endorsement_key_sha256;
        std::string dmi_system_uuid;
        std::string cpu_model_identifier;
        std::string hardware_token_hash;
        uint64_t enrolled_timestamp_ns{0};
    };

    struct HardwareProfile
    {
        std::string profile_id; // x86_64_generic, advantech_uno, nvidia_jetson_orin
        std::string arch;
        std::string tpm_device_path;
        uint32_t default_nic_queues{1};
        uint32_t umem_frame_size{4096};
        uint32_t umem_frame_count{4096};
        bool has_avx512{false};
        bool has_vnni{false};
        bool has_neon{false};
    };

    class TpmEnrollmentManager
    {
    public:
        TpmEnrollmentManager() = default;
        ~TpmEnrollmentManager() = default;

        /// Auto-detects physical hardware capabilities and TPM 2.0 endorsement key
        [[nodiscard]] HardwareProfile detect_hardware_profile() const;

        /// Extracts TPM 2.0 Endorsement Key (EK) or falls back to DMI System UUID
        [[nodiscard]] HardwareIdentityToken generate_hardware_token() const;

        /// Saves hardware identity token to /etc/sentinel/hardware_identity.token
        bool save_hardware_token(const HardwareIdentityToken &token, const std::string &path = "/etc/sentinel/hardware_identity.token") const;

        /// Verifies stored hardware identity token against live physical silicon
        [[nodiscard]] bool verify_hardware_token(const std::string &path = "/etc/sentinel/hardware_identity.token") const;
    };

} // namespace sentinel::hardware