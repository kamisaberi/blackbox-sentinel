#include "ndr_module.hpp"
#include <iostream>

namespace sentinel::modules::ndr {

NdrModule::NdrModule()
    : flow_analyzer_(std::make_unique<FlowAnalyzer>()),
      eta_fingerprinter_(std::make_unique<ETAFingerprinter>()) {}

bool NdrModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 03] NDR 10Gbps Flow Analysis & ETA Engine initialized." << std::endl;
    return true;
}

bool NdrModule::start() {
    running_ = true;
    std::cout << "[Module 03] NDR 10Gbps Flow Analysis & ETA Engine started." << std::endl;
    return true;
}

void NdrModule::stop() {
    running_ = false;
    std::cout << "[Module 03] NDR 10Gbps Flow Analysis & ETA Engine stopped." << std::endl;
}

void NdrModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.type != blackbox::EventType::NetworkPacket) return;

    auto stats = flow_analyzer_->extract_flow_stats(event);
    float c2_score = eta_fingerprinter_->compute_malware_probability(event.features);

    if (c2_score >= 0.85f) {
        event.anomaly_score = std::max(event.anomaly_score, c2_score);
        event.description += " [NDR Alert: Encrypted C2 Beaconing Detected]";
        event.level = blackbox::ThreatLevel::Critical;
    }
}

bool NdrModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ndr