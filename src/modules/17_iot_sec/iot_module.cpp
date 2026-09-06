#include "iot_module.hpp"
#include <iostream>

namespace sentinel::modules::iot_sec {

IotModule::IotModule()
    : dicom_guard_(std::make_unique<DICOMPACSGuard>()),
      hl7_audit_(std::make_unique<HL7TelemetryAudit>()) {}

bool IotModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 17] IoT & Medical Device (IoMT) Defense Engine initialized." << std::endl;
    return true;
}

bool IotModule::start() {
    running_ = true;
    std::cout << "[Module 17] IoT & Medical Device (IoMT) Defense Engine started." << std::endl;
    return true;
}

void IotModule::stop() {
    running_ = false;
    std::cout << "[Module 17] IoT & Medical Device (IoMT) Defense Engine stopped." << std::endl;
}

void IotModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Inspect DICOM Medical Imaging PACS Streams (Port 104)
    if (event.port == 104 || event.description.find("DICOM") != std::string::npos) {
        std::string anomaly;
        if (dicom_guard_->inspect_dicom_packet(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size(),
            anomaly)) {
            event.anomaly_score = 0.98f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::EBPFBlockIP;
            event.description += " [Medical PACS Threat: " + anomaly + "]";
        }
    }

    // Inspect HL7 Hospital Telemetry (Port 2575)
    if (event.port == 2575 || event.description.find("MSH|") != std::string::npos) {
        std::string finding;
        if (hl7_audit_->inspect_mllp_frame(event.description, finding)) {
            event.anomaly_score = 0.96f;
            event.level = blackbox::ThreatLevel::High;
            event.description += " [HL7 Clinical Violation: " + finding + "]";
        }
    }
}

bool IotModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::iot_sec