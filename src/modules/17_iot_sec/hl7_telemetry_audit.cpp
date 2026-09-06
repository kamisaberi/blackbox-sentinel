#include "hl7_telemetry_audit.hpp"

namespace sentinel::modules::iot_sec {

bool HL7TelemetryAudit::inspect_mllp_frame(const std::string& raw_frame, std::string& out_finding) {
    if (raw_frame.empty()) return false;

    // MLLP Framing: Start byte 0x0B (VT), End bytes 0x1C 0x0D (FS CR)
    bool has_start = (raw_frame.front() == 0x0B);
    bool has_end = (raw_frame.size() >= 2 && raw_frame[raw_frame.size() - 2] == 0x1C);

    if (raw_frame.find("MSH|^~\\&") != std::string::npos) {
        if (!has_start && !has_end) {
            out_finding = "HL7 message missing required MLLP transport framing";
            return true;
        }
    }

    // Inspect for SQL injection embedded inside patient identification segments (PID-5)
    if (raw_frame.find("PID|") != std::string::npos) {
        if (raw_frame.find("' OR '") != std::string::npos || raw_frame.find("UNION") != std::string::npos) {
            out_finding = "SQL injection attempt detected inside HL7 Patient Record segment (PID)";
            return true;
        }
    }

    return false;
}

bool HL7TelemetryAudit::check_vital_sign_tampering(double heart_rate, double spo2_percent, std::string& out_finding) {
    // Biological impossibility validation (Sensor spoofing)
    if (heart_rate > 300.0 || (heart_rate < 20.0 && heart_rate > 0.0)) {
        out_finding = "Physiologically impossible heart rate value transmitted: " + std::to_string(static_cast<int>(heart_rate)) + " BPM";
        return true;
    }

    if (spo2_percent > 100.0 || (spo2_percent < 40.0 && spo2_percent > 0.0)) {
        out_finding = "Physiologically impossible SpO2 blood oxygen transmitted: " + std::to_string(static_cast<int>(spo2_percent)) + " %";
        return true;
    }

    return false;
}

} // namespace sentinel::modules::iot_sec