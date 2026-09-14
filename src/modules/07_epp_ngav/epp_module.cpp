#include "epp_module.hpp"
#include <iostream>

namespace sentinel::modules::epp_ngav {

EppModule::EppModule()
    : entropy_calc_(std::make_unique<FileEntropyCalculator>()),
      binary_parser_(std::make_unique<BinaryPEParser>()) {}

bool EppModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 07] EPP/NGAV File Entropy & Antivirus Engine initialized." << std::endl;
    return true;
}

bool EppModule::start() {
    running_ = true;
    std::cout << "[Module 07] EPP/NGAV File Entropy & Antivirus Engine started." << std::endl;
    return true;
}

void EppModule::stop() {
    running_ = false;
    std::cout << "[Module 07] EPP/NGAV File Entropy & Antivirus Engine stopped." << std::endl;
}

void EppModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // If event represents disk I/O file write
    if (event.description.find("FILE_WRITE") != std::string::npos) {
        // Calculate Shannon entropy on event description/payload
        double entropy = entropy_calc_->calculate_entropy(
            reinterpret_cast<const uint8_t*>(event.description.data()), 
            event.description.size()
        );

        if (entropy_calc_->is_ransomware_encrypted(entropy)) {
            event.anomaly_score = 0.99f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::KillProcess;
            event.description += " [NGAV Alert: Active Ransomware File Encryption Intercepted]";
        }
    }
}

bool EppModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::epp_ngav