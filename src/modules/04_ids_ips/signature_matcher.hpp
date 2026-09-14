#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace sentinel::modules::ids_ips {

struct IPSSignature {
    std::string sig_id;
    std::string name;
    uint16_t target_port;
    std::string pattern;
    float threat_weight;
};

class SignatureMatcher {
public:
    SignatureMatcher();
    ~SignatureMatcher() = default;

    void register_signature(const IPSSignature& sig);
    bool match(uint16_t port, const std::string& payload, float& out_weight, std::string& out_match_name);

private:
    std::vector<IPSSignature> signatures_;
    std::mutex matcher_mutex_;
};

} // namespace sentinel::modules::ids_ips