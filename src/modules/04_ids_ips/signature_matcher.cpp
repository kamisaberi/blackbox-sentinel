#include "signature_matcher.hpp"
#include <algorithm>

namespace sentinel::modules::ids_ips {

SignatureMatcher::SignatureMatcher() {
    // Default known attack signatures
    signatures_.push_back({"SIG-1001", "TCP SYN Flood Exploit Pattern", 80, "SYN_FLOOD_ANOMALY", 0.95f});
    signatures_.push_back({"SIG-1002", "SSH Shellcode Execution Attempt", 22, "\x90\x90\x90\x90", 0.98f});
    signatures_.push_back({"SIG-1003", "Modbus Illegal Function Override", 502, "MALICIOUS_MODBUS", 0.99f});
    signatures_.push_back({"SIG-1004", "DNP3 Substation Packet Tampering", 20000, "UNAUTHORIZED_DNP3", 0.97f});
}

void SignatureMatcher::register_signature(const IPSSignature& sig) {
    std::lock_guard<std::mutex> lock(matcher_mutex_);
    signatures_.push_back(sig);
}

bool SignatureMatcher::match(uint16_t port, const std::string& payload, float& out_weight, std::string& out_match_name) {
    if (payload.empty()) return false;

    std::lock_guard<std::mutex> lock(matcher_mutex_);
    for (const auto& sig : signatures_) {
        if (sig.target_port == 0 || sig.target_port == port) {
            if (payload.find(sig.pattern) != std::string::npos) {
                out_weight = sig.threat_weight;
                out_match_name = sig.name;
                return true;
            }
        }
    }
    return false;
}

} // namespace sentinel::modules::ids_ips