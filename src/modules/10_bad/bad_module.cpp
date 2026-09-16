#include "bad_module.hpp"
#include <iostream>

namespace sentinel::modules::bad {

BadModule::BadModule()
    : kinematics_evaluator_(std::make_unique<MouseKeystrokeNN>()),
      tcp_fingerprinter_(std::make_unique<TCPFingerprinter>()) {}

bool BadModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 10] BAD Bot & Automated Abuse Defense Engine initialized." << std::endl;
    return true;
}

bool BadModule::start() {
    running_ = true;
    std::cout << "[Module 10] BAD Bot & Automated Abuse Defense Engine started." << std::endl;
    return true;
}

void BadModule::stop() {
    running_ = false;
    std::cout << "[Module 10] BAD Bot & Automated Abuse Defense Engine stopped." << std::endl;
}

void BadModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Check TCP fingerprinting heuristics
    if (event.type == blackbox::EventType::NetworkPacket) {
        uint16_t win = event.features.size() > 0 ? static_cast<uint16_t>(event.features[0] * 65535.0f) : 1024;
        uint16_t mss = event.features.size() > 1 ? static_cast<uint16_t>(event.features[1] * 1500.0f) : 1460;

        if (tcp_fingerprinter_->is_automated_scanner(win, mss, 64)) {
            event.anomaly_score = std::max(event.anomaly_score, 0.94f);
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::EBPFBlockIP;
            event.description += " [BAD Detection: Automated Mass-Scanner Signature]";
        }
    }

    // Check interaction kinematics
    if (event.description.find("INPUT_TELEMETRY") != std::string::npos) {
        float bot_prob = kinematics_evaluator_->evaluate_bot_probability(event.features);
        if (bot_prob >= 0.85f) {
            event.anomaly_score = std::max(event.anomaly_score, bot_prob);
            event.description += " [BAD Detection: Automated Bot Scripted Movement]";
        }
    }
}

bool BadModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::bad