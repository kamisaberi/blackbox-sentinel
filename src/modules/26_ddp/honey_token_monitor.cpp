#include "honey_token_monitor.hpp"

namespace sentinel::modules::ddp {

HoneyTokenMonitor::HoneyTokenMonitor() {
    honey_tokens_.insert("canary_admin_token_99");
    honey_tokens_.insert("AKIA_CANARY_HONEY_KEY");
    honey_tokens_.insert("/var/backups/passwords_fake.kdbx");
}

bool HoneyTokenMonitor::check_token_access(const std::string& payload, std::string& out_alert) {
    std::lock_guard<std::mutex> lock(token_mutex_);
    for (const auto& token : honey_tokens_) {
        if (payload.find(token) != std::string::npos) {
            out_alert = "Canary HoneyToken triggered: " + token + " was accessed";
            return true;
        }
    }
    return false;
}

} // namespace sentinel::modules::ddp