#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace sentinel::modules::iot_sec {

enum class DICOMCommand {
    Unknown,
    C_STORE_RQ,
    C_FIND_RQ,
    C_MOVE_RQ,
    C_ECHO_RQ
};

class DICOMPACSGuard {
public:
    DICOMPACSGuard() = default;
    ~DICOMPACSGuard() = default;

    DICOMCommand parse_command(const uint8_t* pdu_data, size_t size);
    bool inspect_dicom_packet(const uint8_t* pdu_data, size_t size, std::string& out_anomaly);
};

} // namespace sentinel::modules::iot_sec