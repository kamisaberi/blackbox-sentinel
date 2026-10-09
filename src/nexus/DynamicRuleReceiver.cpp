#include "DynamicRuleReceiver.hpp"
#include <fstream>
#include <iostream>
#include <openssl/pem.h>

namespace sentinel::nexus {

DynamicRuleReceiver::DynamicRuleReceiver(std::filesystem::path rules_dir,
                                         std::filesystem::path wasm_dir,
                                         std::string master_public_key_pem)
    : rules_dir_(std::move(rules_dir)),
      wasm_dir_(std::move(wasm_dir)),
      master_pubkey_pem_(std::move(master_public_key_pem)) {}

bool DynamicRuleReceiver::verify_ed25519_signature(const uint8_t* data,
                                                   size_t data_len,
                                                   const uint8_t* sig_bytes) {
    if (master_pubkey_pem_.empty() || !data || !sig_bytes) return false;

    BIO* bio = BIO_new_mem_buf(master_pubkey_pem_.data(), static_cast<int>(master_pubkey_pem_.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool valid = false;
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        if (EVP_DigestVerify(md_ctx, sig_bytes, 64, data, data_len) == 1) {
            valid = true;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return valid;
}

bool DynamicRuleReceiver::process_and_stage_rule(const std::string& rule_id,
                                                 const std::string& rule_name,
                                                 uint32_t tier,
                                                 const uint8_t* payload_data,
                                                 size_t payload_len,
                                                 const uint8_t* sig_64_bytes,
                                                 std::string& out_error_msg) {
    // 1. Enforce Cryptographic Authenticity Gate
    if (!verify_ed25519_signature(payload_data, payload_len, sig_64_bytes)) {
        out_error_msg = "SIGNATURE VERIFICATION FAILED: Payload rejected or untrusted source";
        return false;
    }

    // 2. Determine target path based on extension tier
    std::filesystem::path target_file;
    if (tier == 2) { // TIER_LUA (EXTENSION_TIER_LUA)
        target_file = rules_dir_ / (rule_id + "_" + rule_name + ".lua");
    } else if (tier == 1) { // TIER_WASM (EXTENSION_TIER_WASM)
        target_file = wasm_dir_ / (rule_id + "_" + rule_name + ".wasm");
    } else {
        out_error_msg = "Unsupported extension tier for dynamic broadcast";
        return false;
    }

    // 3. Atomic File Staging
    std::filesystem::path tmp_file = target_file.string() + ".tmp";
    {
        std::ofstream out(tmp_file, std::ios::binary);
        if (!out.is_open()) {
            out_error_msg = "Failed to open temporary staging file: " + tmp_file.string();
            return false;
        }
        out.write(reinterpret_cast<const char*>(payload_data), payload_len);
        out.flush();
    }

    // Atomic rename triggers Linux inotify on the directory
    std::filesystem::rename(tmp_file, target_file);
    return true;
}

} // namespace sentinel::nexus