#include "cps_module.hpp"
#include <iostream>

namespace sentinel::modules::cps_sec {

CpsModule::CpsModule()
    : modbus_parser_(std::make_unique<ModbusParser>()),
      dnp3_parser_(std::make_unique<DNP3Parser>()),
      physics_validator_(std::make_unique<PhysicsValidator>()) {}

bool CpsModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 18] CPS-Sec Cyber-Physical & SCADA OT Defense Engine initialized." << std::endl;
    return true;
}

bool CpsModule::start() {
    running_ = true;
    std::cout << "[Module 18] CPS-Sec Cyber-Physical & SCADA OT Defense Engine started." << std::endl;
    return true;
}

void CpsModule::stop() {
    running_ = false;
    std::cout << "[Module 18] CPS-Sec Cyber-Physical & SCADA OT Defense Engine stopped." << std::endl;
}

void CpsModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Inspect Modbus SCADA TCP streams (Port 502)
    if (event.port == 502) {
        auto mb_frame = modbus_parser_->parse_mbap(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size()
        );

        if (mb_frame.valid && modbus_parser_->is_write_function(mb_frame.function_code)) {
            // Validate requested physical value
            double requested_val = static_cast<double>(mb_frame.value_or_count);
            std::string violation;
            if (!physics_validator_->validate_chemical_tank_pressure(requested_val, violation)) {
                event.anomaly_score = 0.99f;
                event.level = blackbox::ThreatLevel::Critical;
                event.action_taken = blackbox::ActionType::EBPFBlockIP;
                event.description += " [CPS-Sec Intervention: " + violation + "]";
            }
        }
    }

    // Inspect DNP3 Power Substation Streams (Port 20000)
    if (event.port == 20000) {
        auto dnp3_frame = dnp3_parser_->parse_header(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size()
        );

        if (dnp3_frame.valid && dnp3_parser_->is_control_command(dnp3_frame.function_code)) {
            event.anomaly_score = std::max(event.anomaly_score, 0.95f);
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [DNP3 Grid Substation Control Command Audited]";
        }
    }
}

bool CpsModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::cps_sec