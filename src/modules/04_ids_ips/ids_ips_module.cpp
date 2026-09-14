#include "ids_ips_module.hpp"
#include <iostream>

namespace sentinel::modules::ids_ips {

IdsIpsModule::IdsIpsModule()
    : matcher_(std::make_unique<SignatureMatcher>()),
      dropper_(std::make_unique<XDPPacketDropper>()) {}

bool IdsIpsModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 04] IDS/IPS Inline Prevention Engine initialized." << std::endl;
    return true;
}

bool IdsIpsModule::start() {
    running_ = true;
    std::cout << "[Module 04] IDS/IPS Inline Prevention Engine started." << std::endl;
    return true;
}

void IdsIpsModule::stop() {
    running_ = false;
    std::cout << "[Module 04] IDS/IPS Inline Prevention Engine stopped." << std::endl;
}

void IdsIpsModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.source_ip.empty()) return;

    float sig_weight = 0.0f;
    std::string matched_sig_name;

    if (matcher_->match(event.port, event.description, sig_weight, matched_sig_name)) {
        event.anomaly_score = std::max(event.anomaly_score, sig_weight);
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [IPS Signature Match: " + matched_sig_name + "]";

        dropper_->enforce_drop(event.source_ip);
    }
}

bool IdsIpsModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ids_ips