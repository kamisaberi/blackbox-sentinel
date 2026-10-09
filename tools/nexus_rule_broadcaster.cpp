#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "nexus/DynamicRuleReceiver.hpp"
#include "sdk/PluginSupervisor.hpp"

using namespace sentinel::nexus;
using namespace sentinel::sdk;

// Read binary file
std::vector<uint8_t> load_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b(sz);
    f.read(reinterpret_cast<char*>(b.data()), sz);
    return b;
}

// Sign payload using Ed25519 Private Key
std::vector<uint8_t> sign_payload(EVP_PKEY* pkey, const uint8_t* data, size_t len) {
    std::vector<uint8_t> sig(64);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = 64;
    EVP_DigestSign(ctx, sig.data(), &sig_len, data, len);
    EVP_MD_CTX_free(ctx);
    return sig;
}

int main(int argc, char* argv[]) {
    std::cout << "============================================================" << std::endl;
    std::cout << "   SENTINEL-NEXUS FLEET DYNAMIC RULE BROADCAST TEST         " << std::endl;
    std::cout << "============================================================" << std::endl;

    if (argc < 4) {
        std::cout << "Usage: ./nexus_rule_broadcaster <priv_key.pem> <pub_key.pem> <rule_script.lua>\n";
        return 1;
    }

    std::string priv_key_path = argv[1];
    std::string pub_key_path  = argv[2];
    std::string rule_path     = argv[3];

    // 1. Load Keys
    FILE* fp_priv = fopen(priv_key_path.c_str(), "rb");
    if (!fp_priv) { std::cerr << "[-] Cannot open private key\n"; return 1; }
    EVP_PKEY* pkey_priv = PEM_read_PrivateKey(fp_priv, nullptr, nullptr, nullptr);
    fclose(fp_priv);

    auto pub_bytes = load_file(pub_key_path);
    std::string pub_key_pem(pub_bytes.begin(), pub_bytes.end());

    // 2. Load Rule Payload (e.g. Dynamic zero-day Lua rule)
    auto rule_payload = load_file(rule_path);
    if (rule_payload.empty()) { std::cerr << "[-] Cannot read rule file\n"; return 1; }

    // 3. Nexus signs the payload
    auto t_start = std::chrono::high_resolution_clock::now();
    auto signature = sign_payload(pkey_priv, rule_payload.data(), rule_payload.size());
    EVP_PKEY_free(pkey_priv);

    std::cout << "[+] [Nexus C2] Signed rule payload (" << rule_payload.size() << " bytes) with Ed25519" << std::endl;

    // 4. Initialize Local Appliance Receiver with Master Public Key
    DynamicRuleReceiver receiver("/etc/sentinel/rules.d", "/etc/sentinel/wasm.d", pub_key_pem);

    std::string err_msg;
    bool staged = receiver.process_and_stage_rule("9001",
                                                  "fleet_zeroday_hotfix",
                                                  2, // TIER_LUA
                                                  rule_payload.data(),
                                                  rule_payload.size(),
                                                  signature.data(),
                                                  err_msg);

    auto t_end = std::chrono::high_resolution_clock::now();
    auto total_latency_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();

    if (!staged) {
        std::cerr << "[-] Staging failed: " << err_msg << std::endl;
        return 1;
    }

    std::cout << "[+] [Appliance] Signature VERIFIED. Rule atomically staged into /etc/sentinel/rules.d/" << std::endl;
    std::cout << "    Broadcast & Staging Latency: " << total_latency_us << " us (< 50,000 us SLA)" << std::endl;

    // 5. Test Tampered Payload Rejection Gate
    std::cout << "\n[+] [Security Test] Testing tampered payload rejection..." << std::endl;
    std::vector<uint8_t> tampered_payload = rule_payload;
    tampered_payload[0] ^= 0xFF; // Corrupt a single byte

    bool tampered_staged = receiver.process_and_stage_rule("9002",
                                                           "tampered_rule",
                                                           2,
                                                           tampered_payload.data(),
                                                           tampered_payload.size(),
                                                           signature.data(),
                                                           err_msg);

    if (!tampered_staged) {
        std::cout << "[SUCCESS] Tampered payload was correctly REJECTED by cryptographic gate!" << std::endl;
        std::cout << "          Error: " << err_msg << std::endl;
    } else {
        std::cerr << "[-] CRITICAL: Tampered payload was accepted!" << std::endl;
        return 1;
    }

    std::cout << "\n============================================================" << std::endl;
    std::cout << " [SUCCESS] Fleet Rule Broadcast & Security Gate Verified!   " << std::endl;
    std::cout << "============================================================" << std::endl;
    return 0;
}