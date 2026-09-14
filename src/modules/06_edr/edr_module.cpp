#include "edr_module.hpp"
#include <iostream>

namespace sentinel::modules::edr {

EdrModule::EdrModule()
    : process_tracker_(std::make_unique<ProcessTracker>()),
      memory_scanner_(std::make_unique<MemoryScanner>()) {}

bool EdrModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 06] EDR Host Endpoint Defense Engine initialized." << std::endl;
    return true;
}

bool EdrModule::start() {
    running_ = true;
    std::cout << "[Module 06] EDR Host Endpoint Defense Engine started." << std::endl;
    return true;
}

void EdrModule::stop() {
    running_ = false;
    std::cout << "[Module 06] EDR Host Endpoint Defense Engine stopped." << std::endl;
}

void EdrModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.type != blackbox::EventType::SystemLog) return;

    // Simulate process tracker inspection from Auditd lines
    if (event.description.find("EXECVE") != std::string::npos) {
        process_tracker_->register_process(2048, 1024, "bash", "/bin/bash -i");
        std::string reason;
        if (process_tracker_->is_suspicious_lineage(2048, reason)) {
            event.anomaly_score = 0.98f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::KillProcess;
            event.description += " [EDR Alert: " + reason + "]";
        }
    }
}

bool EdrModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::edr