#include "kerberos_watcher.hpp"

namespace sentinel::modules::itdr {

bool KerberosWatcher::detect_kerberoasting(const std::string& account_name, uint32_t enc_type, uint32_t ticket_options, std::string& out_violation) {
    std::lock_guard<std::mutex> lock(kerberos_mutex_);

    // Check for downgrade to legacy RC4-HMAC (type 23) which is vulnerable to offline cracking
    if (enc_type == static_cast<uint32_t>(EncryptionType::RC4_HMAC)) {
        request_counts_[account_name]++;
        if (request_counts_[account_name] >= 3) {
            out_violation = "Kerberoasting TGS request burst targeting account " + account_name + " with RC4-HMAC downgrade";
            return true;
        }
    }

    // SPN query without typical workstation flags
    if ((ticket_options & 0x40800000) != 0 && enc_type == 23) {
        out_violation = "Suspicious SPN ticket request with abnormal options mask";
        return true;
    }

    return false;
}

bool KerberosWatcher::detect_golden_ticket(uint32_t ticket_lifetime_hours, const std::string& domain_sid) {
    (void)domain_sid;
    // Standard Active Directory Kerberos ticket lifetime is 10 hours; forged tickets often specify 10+ years
    if (ticket_lifetime_hours > 24) {
        return true;
    }
    return false;
}

} // namespace sentinel::modules::itdr