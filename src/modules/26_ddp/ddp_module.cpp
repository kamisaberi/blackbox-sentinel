#include "ddp_module.hpp"
#include <iostream>

namespace sentinel::modules::ddp {

DdpModule::DdpModule()
    : plc_trap_(std::make_unique<DecoyPLCTrap>()),
      ssh_trap_(std::make_unique<DecoySSHTrap>()),
      token_monitor_(std::make_unique<HoneyTokenMonitor>()) {}

bool DdpModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 26] DDP Distributed Deception & Honeypot Grid initialized." << std::endl;
    return true;
}

bool DdpModule::start() {
    running_ = true;
    std::cout << "[Module 26] DDP Distributed Deception & Honeypot Grid started." << std::endl;
    return true;
}

void DdpModule::stop() {
    running_ = false;
    std::cout << "[Module 26] DDP Distributed Deception & Honeypot Grid stopped." << std::endl;
}

void DdpModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Check decoy honeypot ports
    if (ssh_trap_->record_connection(event.source_ip, event.port)) {
        event.anomaly_score = 1.00f; // Instant drop on honeypot touch
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [DDP Trap: Attacker probe intercepted on Decoy Port " + std::to_string(event.port) + "]";
    }

    // Check decoy PLC interaction
    std::string plc_alert;
    if (plc_trap_->handle_probe(event.port, event.description, plc_alert)) {
        event.anomaly_score = 1.00f;
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [DDP Alert: " + plc_alert + "]";
    }

    // Check canary tokens
    std::string token_alert;
    if (token_monitor_->check_token_access(event.description, token_alert)) {
        event.anomaly_score = 0.99f;
        event.level = blackbox::ThreatLevel::Critical;
        event.description += " [DDP Alert: " + token_alert + "]";
    }
}

bool DdpModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ddp