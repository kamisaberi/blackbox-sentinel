#include "fse_module.hpp"
#include <iostream>

namespace sentinel::modules::fse {

FseModule::FseModule()
    : uefi_parser_(std::make_unique<UEFIImageParser>()),
      backdoor_scanner_(std::make_unique<BackdoorScanner>()) {}

bool FseModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 20] FSE Firmware Security Evaluation Engine initialized." << std::endl;
    return true;
}

bool FseModule::start() {
    running_ = true;
    std::cout << "[Module 20] FSE Firmware Security Evaluation Engine started." << std::endl;
    return true;
}

void FseModule::stop() {
    running_ = false;
    std::cout << "[Module 20] FSE Firmware Security Evaluation Engine stopped." << std::endl;
}

void FseModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("FIRMWARE_IMAGE") != std::string::npos) {
        std::string finding;
        const auto* raw_ptr = reinterpret_cast<const uint8_t*>(event.description.data());
        size_t size = event.description.size();

        if (backdoor_scanner_->scan_for_rootkit_signatures(raw_ptr, size, finding)) {
            event.anomaly_score = 1.00f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [FSE Alert: " + finding + "]";
        }
    }
}

bool FseModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::fse