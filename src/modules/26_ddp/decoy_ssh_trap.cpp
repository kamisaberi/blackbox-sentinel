#include "decoy_ssh_trap.hpp"

namespace sentinel::modules::ddp {

bool DecoySSHTrap::record_connection(const std::string& src_ip, uint16_t port) {
    if (src_ip.empty()) return false;

    // Standard honeypot ports: 2222 (decoy SSH), 23 (decoy Telnet)
    if (port == 2222 || port == 23) {
        std::lock_guard<std::mutex> lock(ssh_trap_mutex_);
        trapped_ips_[src_ip]++;
        return true; // Malicious probe trapped
    }
    return false;
}

size_t DecoySSHTrap::trapped_attacker_count() {
    std::lock_guard<std::mutex> lock(ssh_trap_mutex_);
    return trapped_ips_.size();
}

} // namespace sentinel::modules::ddp