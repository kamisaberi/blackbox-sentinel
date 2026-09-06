#include "swg_module.hpp"
#include <iostream>

namespace sentinel::modules::swg {

SwgModule::SwgModule()
    : url_classifier_(std::make_unique<URLClassifier>()),
      proxy_checker_(std::make_unique<OutboundProxy>()) {}

bool SwgModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 19] SWG Secure Web Gateway Engine initialized." << std::endl;
    return true;
}

bool SwgModule::start() {
    running_ = true;
    std::cout << "[Module 19] SWG Secure Web Gateway Engine started." << std::endl;
    return true;
}

void SwgModule::stop() {
    running_ = false;
    std::cout << "[Module 19] SWG Secure Web Gateway Engine stopped." << std::endl;
}

void SwgModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Check outbound URL categories
    std::string category;
    if (url_classifier_->is_malicious_url(event.description, category)) {
        event.anomaly_score = 0.95f;
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [SWG Web Quarantine: " + category + "]";
    }

    // Check unauthorized egress port tunnels
    std::string reason;
    if (proxy_checker_->is_unauthorized_egress(event.port, event.destination_ip, reason)) {
        event.anomaly_score = std::max(event.anomaly_score, 0.92f);
        event.level = blackbox::ThreatLevel::High;
        event.description += " [SWG Egress Alert: " + reason + "]";
    }
}

bool SwgModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::swg