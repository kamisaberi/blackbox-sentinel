#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace sentinel::modules::itdr {

enum class EncryptionType {
    RC4_HMAC = 23,
    AES128_CTS_HMAC_SHA1 = 17,
    AES256_CTS_HMAC_SHA1 = 18,
    Unknown = 0
};

class KerberosWatcher {
public:
    KerberosWatcher() = default;
    ~KerberosWatcher() = default;

    // Evaluates Kerberos TGS/TGT ticket request characteristics
    bool detect_kerberoasting(const std::string& account_name, uint32_t enc_type, uint32_t ticket_options, std::string& out_violation);
    bool detect_golden_ticket(uint32_t ticket_lifetime_hours, const std::string& domain_sid);

private:
    std::unordered_map<std::string, uint32_t> request_counts_;
    std::mutex kerberos_mutex_;
};

} // namespace sentinel::modules::itdr