#include "ztna_module.hpp"
#include <iostream>

namespace sentinel::modules::ztna {

ZtnaModule::ZtnaModule()
    : trust_calc_(std::make_unique<DynamicTrustCalculator>()),
      enforcer_(std::make_unique<MicrosegmentEnforcer>()) {}

bool ZtnaModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 24] ZTNA Zero Trust Dynamic Access Control initialized." << std::endl;
    return true;
}

bool ZtnaModule::start() {
    running_ = true;
    std::cout << "[Module 24] ZTNA Zero Trust Dynamic Access Control started." << std::endl;
    return true;
}

void ZtnaModule::stop() {
    running_ = false;
    std::cout << "[Module 24] ZTNA Zero Trust Dynamic Access Control stopped." << std::endl;
}

void ZtnaModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.source_ip.empty()) return;

    // Recalculate continuous trust score based on observed event anomaly score
    uint32_t current_trust = trust_calc_->evaluate_trust(event.source_ip, event.anomaly_score);

    std::string action_desc;
    if (enforcer_->enforce_policy(event.source_ip, current_trust, action_desc)) {
        if (current_trust < 20) {
            event.anomaly_score = 0.99f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::EBPFBlockIP;
        }
        event.description += " [ZTNA Trust Score: " + std::to_string(current_trust) + "/100 -> " + action_desc + "]";
    }
}

bool ZtnaModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ztna