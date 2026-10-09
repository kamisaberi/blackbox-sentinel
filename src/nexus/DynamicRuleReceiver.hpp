#pragma once

#include "sentinel/sdk/abi.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>

namespace sentinel::nexus {

class DynamicRuleReceiver {
public:
    DynamicRuleReceiver(std::filesystem::path rules_dir,
                        std::filesystem::path wasm_dir,
                        std::string master_public_key_pem);
    ~DynamicRuleReceiver() = default;

    DynamicRuleReceiver(const DynamicRuleReceiver&) = delete;
    DynamicRuleReceiver& operator=(const DynamicRuleReceiver&) = delete;

    /// Validates Ed25519 signature and stages rule into active engine directory
    bool process_and_stage_rule(const std::string& rule_id,
                                const std::string& rule_name,
                                uint32_t tier,
                                const uint8_t* payload_data,
                                size_t payload_len,
                                const uint8_t* sig_64_bytes,
                                std::string& out_error_msg);

private:
    bool verify_ed25519_signature(const uint8_t* data,
                                  size_t data_len,
                                  const uint8_t* sig_bytes);

    std::filesystem::path rules_dir_;
    std::filesystem::path wasm_dir_;
    std::string master_pubkey_pem_;
};

} // namespace sentinel::nexus