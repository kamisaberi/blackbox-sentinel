#include "side_channel_module.hpp"
#include <iostream>

namespace sentinel::modules::side_channel {

SideChannelModule::SideChannelModule()
    : power_evaluator_(std::make_unique<PowerTraceEvaluator>()),
      em_detector_(std::make_unique<EMNoiseDetector>()) {}

bool SideChannelModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 21] Side-Channel Physical Defense Engine initialized." << std::endl;
    return true;
}

bool SideChannelModule::start() {
    running_ = true;
    std::cout << "[Module 21] Side-Channel Physical Defense Engine started." << std::endl;
    return true;
}

void SideChannelModule::stop() {
    running_ = false;
    std::cout << "[Module 21] Side-Channel Physical Defense Engine stopped." << std::endl;
}

void SideChannelModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("SIDE_CHANNEL_TELEMETRY") != std::string::npos) {
        float variance = 0.0f;
        if (power_evaluator_->detect_dpa_anomaly(event.features, variance)) {
            event.anomaly_score = 0.97f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [Side-Channel Alert: Differential Power Analysis Cryptanalysis Target]";
        }

        if (em_detector_->detect_sema_leakage(event.features, 20.0f)) {
            event.anomaly_score = 0.94f;
            event.description += " [Side-Channel Alert: Anomalous High SNR Electromagnetic Emission Spike]";
        }
    }
}

bool SideChannelModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::side_channel