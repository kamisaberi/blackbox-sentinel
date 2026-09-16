#include "nac_module.hpp"
#include <iostream>

namespace sentinel::modules::nac {

NacModule::NacModule()
    : fingerprinter_(std::make_unique<DeviceFingerprinter>()),
      isolator_(std::make_unique<VLANIsolator>(999)) {}

bool NacModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 08] NAC Device Access Control & Fingerprinting initialized." << std::endl;
    return true;
}

bool NacModule::start() {
    running_ = true;
    std::cout << "[Module 08] NAC Device Access Control & Fingerprinting started." << std::endl;
    return true;
}

void NacModule::stop() {
    running_ = false;
    std::cout << "[Module 08] NAC Device Access Control & Fingerprinting stopped." << std::endl;
}

void NacModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.source_ip.empty()) return;

    if (event.description.find("DHCP") != std::string::npos || event.description.find("HANDSHAKE") != std::string::npos) {
        auto fp = fingerprinter_->analyze_handshake(event.source_ip, event.description, 64);

        if (fp.category == DeviceCategory::RogueDevice || fp.trust_score < 0.20f) {
            std::string action_desc;
            isolator_->isolate_device(event.source_ip, action_desc);

            event.anomaly_score = 0.98f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::EBPFBlockIP;
            event.description += " [NAC Enforcement: " + action_desc + " (Identified: " + 
                                 fingerprinter_->category_to_string(fp.category) + ")]";
        }
    }
}

bool NacModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::nac