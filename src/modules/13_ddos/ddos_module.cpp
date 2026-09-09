#include "ddos_module.hpp"
#include <iostream>

namespace sentinel::modules::ddos {

DdosModule::DdosModule()
    : syn_guard_(std::make_unique<SYNFloodGuard>(2000)),
      udp_limiter_(std::make_unique<UDPRateLimiter>(50000, 10000.0)) {}

bool DdosModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 13] Hardware Line-Rate DDoS Mitigation Engine initialized." << std::endl;
    return true;
}

bool DdosModule::start() {
    running_ = true;
    std::cout << "[Module 13] Hardware Line-Rate DDoS Mitigation Engine started." << std::endl;
    return true;
}

void DdosModule::stop() {
    running_ = false;
    std::cout << "[Module 13] Hardware Line-Rate DDoS Mitigation Engine stopped." << std::endl;
}

void DdosModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.type != blackbox::EventType::NetworkPacket) return;

    double syn_rate = 0.0;
    if (syn_guard_->evaluate_syn_packet(event.source_ip, syn_rate)) {
        event.anomaly_score = 0.99f;
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [DDoS Alert: High-Velocity SYN Flood (" + std::to_string(static_cast<int>(syn_rate)) + " packets/sec)]";
    }

    size_t packet_size = event.features.size() > 1 ? static_cast<size_t>(event.features[1] * 1500.0f) : 1024;
    if (!udp_limiter_->check_packet(event.source_ip, packet_size)) {
        event.anomaly_score = std::max(event.anomaly_score, 0.95f);
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [DDoS Alert: UDP Volumetric Flood Exceeded]";
    }
}

bool DdosModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ddos