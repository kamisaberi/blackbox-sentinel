#pragma once

#include <string>
#include <vector>

namespace sentinel::modules::iot_sec {

class HL7TelemetryAudit {
public:
    HL7TelemetryAudit() = default;
    ~HL7TelemetryAudit() = default;

    // Inspects Minimal Lower Layer Protocol (MLLP) framed HL7 v2 telemetry streams
    bool inspect_mllp_frame(const std::string& raw_frame, std::string& out_finding);
    bool check_vital_sign_tampering(double heart_rate, double spo2_percent, std::string& out_finding);
};

} // namespace sentinel::modules::iot_sec