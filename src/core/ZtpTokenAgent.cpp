#include "ZtpTokenAgent.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <sys/utsname.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace sentinel::core {

std::string ZtpTokenAgent::read_sysfs_string(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::string line;
    std::getline(file, line);
    size_t s = line.find_first_not_of(" \t\r\n");
    size_t e = line.find_last_not_of(" \t\r\n");
    return (s != std::string::npos && e != std::string::npos) ? line.substr(s, e - s + 1) : "";
}

std::string ZtpTokenAgent::compute_sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string ZtpTokenAgent::base64_encode(const std::string& input) {
    int max_len = 4 * ((static_cast<int>(input.size()) + 2) / 3);
    std::string out;
    out.resize(max_len);
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                 reinterpret_cast<const unsigned char*>(input.data()),
                                 static_cast<int>(input.size()));
    out.resize(written);
    return out;
}

std::string ZtpTokenAgent::base64_decode(const std::string& input) {
    if (input.empty()) return "";
    int max_len = (static_cast<int>(input.size()) * 3) / 4;
    std::string out;
    out.resize(max_len);
    int decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                 reinterpret_cast<const unsigned char*>(input.data()),
                                 static_cast<int>(input.size()));
    if (decoded < 0) return "";
    // Adjust padding
    int pad = 0;
    if (input.size() >= 1 && input[input.size() - 1] == '=') pad++;
    if (input.size() >= 2 && input[input.size() - 2] == '=') pad++;
    out.resize(decoded - pad);
    return out;
}

HardwareProfile ZtpTokenAgent::probe_hardware_profile() {
    HardwareProfile profile{};
    profile.probed_at_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    // 1. Read Hostname and Kernel Release
    struct utsname u_buf{};
    if (uname(&u_buf) == 0) {
        profile.kernel_release = u_buf.release;
    } else {
        profile.kernel_release = "linux-generic";
    }

    // 2. Read Motherboard DMI / Machine-ID
    profile.machine_uuid = read_sysfs_string("/sys/class/dmi/id/product_uuid");
    if (profile.machine_uuid.empty()) {
        profile.machine_uuid = read_sysfs_string("/etc/machine-id");
    }
    if (profile.machine_uuid.empty()) {
        profile.machine_uuid = "00000000-0000-0000-0000-000000000000";
    }

    profile.system_vendor = read_sysfs_string("/sys/class/dmi/id/sys_vendor");
    if (profile.system_vendor.empty()) profile.system_vendor = "Generic OEM";

    profile.board_serial = read_sysfs_string("/sys/class/dmi/id/board_serial");
    if (profile.board_serial.empty()) profile.board_serial = "SN-DEFAULT-00";

    // 3. Probe Hardware TPM 2.0 Interface
    std::ifstream tpm_dev("/dev/tpmrm0");
    if (tpm_dev.is_open()) {
        profile.tier = HardwareSecurityTier::PHYSICAL_TPM2;
        // Hash physical device parameters as silicon anchor
        std::string tpm_seed = profile.machine_uuid + profile.board_serial + "TPM2_HW_ROOT";
        profile.tpm_fingerprint = compute_sha256_hex(tpm_seed);
    } else {
        // Check for hypervisor signatures (VMware, QEMU, KVM)
        if (profile.system_vendor.find("VMware") != std::string::npos ||
            profile.system_vendor.find("QEMU") != std::string::npos) {
            profile.tier = HardwareSecurityTier::VIRTUAL_TPM;
            profile.tpm_fingerprint = compute_sha256_hex(profile.machine_uuid + "VTPM_HYPERVISOR");
        } else {
            profile.tier = HardwareSecurityTier::DMI_SOFTWARE_FALLBACK;
            profile.tpm_fingerprint = compute_sha256_hex(profile.machine_uuid + profile.board_serial);
        }
    }

    return profile;
}

std::string ZtpTokenAgent::generate_provisioning_token(const std::string& tenant_hint) {
    HardwareProfile p = probe_hardware_profile();

    std::ostringstream ss;
    ss << "{\n"
       << "  \"v\": 1,\n"
       << "  \"tenant\": \"" << tenant_hint << "\",\n"
       << "  \"uuid\": \"" << p.machine_uuid << "\",\n"
       << "  \"vendor\": \"" << p.system_vendor << "\",\n"
       << "  \"serial\": \"" << p.board_serial << "\",\n"
       << "  \"kernel\": \"" << p.kernel_release << "\",\n"
       << "  \"tier\": " << static_cast<int>(p.tier) << ",\n"
       << "  \"tpm_fp\": \"" << p.tpm_fingerprint << "\",\n"
       << "  \"ts\": " << p.probed_at_sec << "\n"
       << "}";

    std::string json_raw = ss.str();
    std::string b64_token = base64_encode(json_raw);
    return "ZTP-" + b64_token;
}

bool ZtpTokenAgent::verify_token_locally(const std::string& ztp_token) {
    if (ztp_token.rfind("ZTP-", 0) != 0) return false;
    std::string b64 = ztp_token.substr(4);
    std::string json_raw = base64_decode(b64);
    if (json_raw.empty()) return false;

    // Check if UUID matches this physical machine
    HardwareProfile local = probe_hardware_profile();
    size_t u_pos = json_raw.find("\"uuid\":");
    if (u_pos == std::string::npos) return false;

    size_t s = json_raw.find('"', u_pos + 7);
    size_t e = json_raw.find('"', s + 1);
    if (s == std::string::npos || e == std::string::npos) return false;

    std::string token_uuid = json_raw.substr(s + 1, e - s - 1);
    return (token_uuid == local.machine_uuid);
}

} // namespace sentinel::core