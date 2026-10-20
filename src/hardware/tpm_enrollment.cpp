#include "sentinel/hardware/tpm_enrollment.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <openssl/evp.h>

namespace fs = std::filesystem;

namespace sentinel::hardware
{

    static std::string sha256_string(const std::string &input)
    {
        std::vector<uint8_t> hash(32);
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, input.data(), input.size());
        unsigned int out_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
        EVP_MD_CTX_free(ctx);

        std::ostringstream ss;
        for (uint8_t b : hash)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }

    HardwareProfile TpmEnrollmentManager::detect_hardware_profile() const
    {
        HardwareProfile profile{};

#if defined(__x86_64__)
        profile.arch = "x86_64";
        profile.profile_id = "x86_64_generic";
#elif defined(__aarch64__)
        profile.arch = "aarch64";
        profile.profile_id = "nvidia_jetson_orin";
        profile.has_neon = true;
#else
        profile.arch = "unknown";
        profile.profile_id = "generic";
#endif

        if (fs::exists("/dev/tpmrm0"))
        {
            profile.tpm_device_path = "/dev/tpmrm0";
        }
        else if (fs::exists("/dev/tpm0"))
        {
            profile.tpm_device_path = "/dev/tpm0";
        }

        // Check CPU vector capabilities
        std::ifstream cpuinfo("/proc/cpuinfo");
        if (cpuinfo.is_open())
        {
            std::string line;
            while (std::getline(cpuinfo, line))
            {
                if (line.find("avx512") != std::string::npos)
                    profile.has_avx512 = true;
                if (line.find("avx_vnni") != std::string::npos || line.find("vnni") != std::string::npos)
                    profile.has_vnni = true;
            }
        }

        return profile;
    }

    HardwareIdentityToken TpmEnrollmentManager::generate_hardware_token() const
    {
        HardwareIdentityToken token{};

        // 1. Try reading TPM 2.0 endorsement key hash
        if (fs::exists("/dev/tpmrm0") || fs::exists("/dev/tpm0"))
        {
            std::string tpm_path = fs::exists("/dev/tpmrm0") ? "/dev/tpmrm0" : "/dev/tpm0";
            std::ifstream tpm_dev(tpm_path, std::ios::binary);
            if (tpm_dev.is_open())
            {
                char buf[64];
                tpm_dev.read(buf, sizeof(buf));
                token.tpm_endorsement_key_sha256 = sha256_string(std::string(buf, tpm_dev.gcount()));
                token.tpm_attested = true;
            }
        }

        // 2. Fallback to DMI System UUID if TPM hardware isn't directly readable
        if (fs::exists("/sys/class/dmi/id/product_uuid"))
        {
            std::ifstream uuid_f("/sys/class/dmi/id/product_uuid");
            std::getline(uuid_f, token.dmi_system_uuid);
        }
        else
        {
            token.dmi_system_uuid = "VMWARE-VIRTUAL-UUID-00000000";
        }

        // 3. Extract CPU model identifier
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line))
        {
            if (line.find("model name") != std::string::npos || line.find("Hardware") != std::string::npos)
            {
                token.cpu_model_identifier = line;
                break;
            }
        }

        // 4. Generate combined hardware token hash
        std::string combined_raw = token.tpm_endorsement_key_sha256 + ":" + token.dmi_system_uuid + ":" + token.cpu_model_identifier;
        token.hardware_token_hash = "HWTOKEN-TPM2-" + sha256_string(combined_raw).substr(0, 32);

        return token;
    }

    bool TpmEnrollmentManager::save_hardware_token(const HardwareIdentityToken &token, const std::string &path) const
    {
        try
        {
            fs::create_directories(fs::path(path).parent_path());
            std::ofstream f(path);
            if (!f.is_open())
                return false;

            f << "{\n"
              << "  \"tpm_attested\": " << (token.tpm_attested ? "true" : "false") << ",\n"
              << "  \"tpm_ek_sha256\": \"" << token.tpm_endorsement_key_sha256 << "\",\n"
              << "  \"dmi_system_uuid\": \"" << token.dmi_system_uuid << "\",\n"
              << "  \"hardware_token_hash\": \"" << token.hardware_token_hash << "\"\n"
              << "}\n";
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool TpmEnrollmentManager::verify_hardware_token(const std::string &path) const
    {
        if (!fs::exists(path))
            return false;
        HardwareIdentityToken current_token = generate_hardware_token();

        std::ifstream f(path);
        std::string line, saved_hash = "";
        while (std::getline(f, line))
        {
            size_t pos = line.find("\"hardware_token_hash\"");
            if (pos != std::string::npos)
            {
                size_t colon = line.find(':', pos);
                size_t start = line.find('"', colon + 1);
                size_t end = line.find('"', start + 1);
                if (start != std::string::npos && end != std::string::npos)
                {
                    saved_hash = line.substr(start + 1, end - start - 1);
                }
            }
        }

        return (!saved_hash.empty() && saved_hash == current_token.hardware_token_hash);
    }

} // namespace sentinel::hardware