#include "LicenseManager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <openssl/evp.h>

namespace sentinel::licensing {

// Master Aryorithm Ed25519 Public Verification Key (Matches DEFAULT_PRIVATE_SEED_HEX)
static const uint8_t ARYORITHM_MASTER_PUBKEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const std::unordered_set<std::string> COMMUNITY_MODULES = {
    "01_siem_core", "04_ids_ips", "15_ngfw", "19_swg", "22_dfir"
};

LicenseManager::LicenseManager() {
    claims_.tier = LicenseTier::COMMUNITY_FREE;
    claims_.authorized_modules = COMMUNITY_MODULES;
}

std::string LicenseManager::probe_local_hardware_uuid() {
    std::string uuid = "00000000-0000-0000-0000-000000000000";
    std::ifstream dmi("/sys/class/dmi/id/product_uuid");
    if (dmi.is_open()) {
        std::getline(dmi, uuid);
    } else {
        std::ifstream mid("/etc/machine-id");
        if (mid.is_open()) std::getline(mid, uuid);
    }
    size_t start = uuid.find_first_not_of(" \t\r\n");
    size_t end = uuid.find_last_not_of(" \t\r\n");
    return (start != std::string::npos && end != std::string::npos) ? uuid.substr(start, end - start + 1) : uuid;
}

std::string LicenseManager::generate_hardware_token() {
    return "ARY-HW-" + probe_local_hardware_uuid();
}

// Clean, robust Base64 decoder using EVP_DecodeBlock
static std::vector<uint8_t> base64_decode(const std::string& input) {
    std::string clean;
    clean.reserve(input.size());
    for (char c : input) {
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t') {
            clean += c;
        }
    }
    if (clean.empty() || clean.size() % 4 != 0) return {};

    int out_len = static_cast<int>((clean.size() / 4) * 3);
    std::vector<uint8_t> out(out_len);
    int decoded = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(clean.data()), static_cast<int>(clean.size()));
    if (decoded < 0) return {};

    if (clean.size() >= 1 && clean[clean.size() - 1] == '=') out_len--;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') out_len--;
    out.resize(out_len);
    return out;
}

bool LicenseManager::verify_ed25519_signature(const std::string& payload_b64, const std::string& b64_sig) {
    auto sig_bytes = base64_decode(b64_sig);
    if (sig_bytes.size() != 64) {
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, ARYORITHM_MASTER_PUBKEY, 32
    );
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool verified = false;

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        if (EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                             reinterpret_cast<const unsigned char*>(payload_b64.data()),
                             payload_b64.size()) == 1) {
            verified = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return verified;
}

static std::string extract_value(const std::string& json, const std::string& key) {
    size_t k = json.find("\"" + key + "\"");
    if (k == std::string::npos) return "";
    size_t colon = json.find(':', k);
    size_t s = json.find('"', colon + 1);
    size_t e = json.find('"', s + 1);
    if (s != std::string::npos && e != std::string::npos) {
        return json.substr(s + 1, e - s - 1);
    }
    return "";
}

bool LicenseManager::load_and_verify(const std::string& license_file_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(license_file_path);
    if (!file.is_open()) {
        std::cout << "[LicenseManager] No license file found at " << license_file_path 
                  << ". Operating in Community Free Tier." << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        license_valid_ = false;
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::string payload_b64 = extract_value(content, "payload_b64");
    std::string signature_b64 = extract_value(content, "signature_b64");

    if (payload_b64.empty() || signature_b64.empty()) {
        std::cerr << "[LicenseManager] Corrupted license: Missing payload or signature." << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        return false;
    }

    // 1. Cryptographic Signature Verification
    if (!verify_ed25519_signature(payload_b64, signature_b64)) {
        std::cerr << "\033[31m[LicenseManager] CRITICAL: Invalid cryptographic signature! "
                  << "License tampering detected. Reverting to Community Tier.\033[0m" << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        return false;
    }

    // 2. Decode claims
    auto claims_bytes = base64_decode(payload_b64);
    std::string claims_json(claims_bytes.begin(), claims_bytes.end());

    // 3. Expiration Check
    std::string exp_str;
    size_t exp_pos = claims_json.find("\"expires_at\":");
    if (exp_pos != std::string::npos) {
        size_t comma = claims_json.find_first_of(",}", exp_pos);
        exp_str = claims_json.substr(exp_pos + 13, comma - exp_pos - 13);
        exp_str.erase(0, exp_str.find_first_not_of(" \t"));
        exp_str.erase(exp_str.find_last_not_of(" \t") + 1);
    }
    uint64_t expires_sec = exp_str.empty() ? 0 : std::stoull(exp_str);
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (expires_sec > 0 && static_cast<uint64_t>(now_sec) > expires_sec) {
        std::cerr << "\033[33m[LicenseManager] License expired on timestamp " << expires_sec 
                  << ". Reverting to Community Tier.\033[0m" << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        return false;
    }

    // 4. Hardware Lock Check
    std::string hw_lock = extract_value(claims_json, "locked_hardware_uuid");
    if (!hw_lock.empty()) {
        std::string local_hw = probe_local_hardware_uuid();
        if (local_hw != hw_lock) {
            std::cerr << "\033[31m[LicenseManager] HARDWARE LOCK VIOLATION: License is bound to [" 
                      << hw_lock << "], but running on [" << local_hw << "]!\033[0m" << std::endl;
            claims_.tier = LicenseTier::COMMUNITY_FREE;
            claims_.authorized_modules = COMMUNITY_MODULES;
            return false;
        }
    }

    // 5. Populate Claims
    claims_.license_id = extract_value(claims_json, "license_id");
    claims_.customer_name = extract_value(claims_json, "customer");
    claims_.locked_hardware_uuid = hw_lock;
    claims_.expires_at_sec = expires_sec;

    std::string tier_str = extract_value(claims_json, "tier");
    if (tier_str == "CRITICAL_OT" || tier_str == "SOVEREIGN_DEFENSE") {
        claims_.tier = LicenseTier::CRITICAL_INFRASTRUCTURE_OT;
    } else {
        claims_.tier = LicenseTier::ENTERPRISE_IT;
    }

    license_valid_ = true;
    std::cout << "\033[32m[LicenseManager] VALID LICENSE VERIFIED: Customer [" << claims_.customer_name 
              << "] | Tier: " << get_tier_name() << "\033[0m" << std::endl;
    return true;
}

bool LicenseManager::is_module_authorized(const std::string& module_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claims_.tier == LicenseTier::CRITICAL_INFRASTRUCTURE_OT || 
        claims_.tier == LicenseTier::SOVEREIGN_DEFENSE) {
        return true;
    }
    if (claims_.tier == LicenseTier::COMMUNITY_FREE) {
        return COMMUNITY_MODULES.contains(module_name);
    }
    static const std::unordered_set<std::string> OT_RESTRICTED = {
        "17_iot_sec", "18_cps_sec", "20_fse", "21_side_channel", "26_ddp"
    };
    return !OT_RESTRICTED.contains(module_name);
}

bool LicenseManager::is_plugin_authorized(const std::string& plugin_filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claims_.tier == LicenseTier::CRITICAL_INFRASTRUCTURE_OT || 
        claims_.tier == LicenseTier::SOVEREIGN_DEFENSE) {
        return true;
    }
    if (claims_.tier == LicenseTier::ENTERPRISE_IT) {
        return (plugin_filename.find("forwarder") != std::string::npos || 
                plugin_filename.find("kafka") != std::string::npos ||
                plugin_filename.find("syslog") != std::string::npos);
    }
    return false;
}

LicenseTier LicenseManager::get_active_tier() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return claims_.tier;
}

std::string LicenseManager::get_tier_name() const {
    switch (claims_.tier) {
        case LicenseTier::COMMUNITY_FREE: return "Community Free Tier";
        case LicenseTier::ENTERPRISE_IT: return "Enterprise IT Edition";
        case LicenseTier::CRITICAL_INFRASTRUCTURE_OT: return "Critical Infrastructure OT (Full 26 Modules & 30 Plugins)";
        case LicenseTier::SOVEREIGN_DEFENSE: return "Sovereign Defense Enclave";
    }
    return "Unknown";
}

} // namespace sentinel::licensing