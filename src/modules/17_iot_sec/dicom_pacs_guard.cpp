#include "dicom_pacs_guard.hpp"
#include <cstring>

namespace sentinel::modules::iot_sec {

DICOMCommand DICOMPACSGuard::parse_command(const uint8_t* pdu_data, size_t size) {
    if (!pdu_data || size < 10) return DICOMCommand::Unknown;

    // Check PDU Type 0x04 (P-DATA-TF)
    if (pdu_data[0] == 0x04) {
        return DICOMCommand::C_STORE_RQ;
    }

    // Check PDU Type 0x01 (A-ASSOCIATE-RQ)
    if (pdu_data[0] == 0x01) {
        return DICOMCommand::C_FIND_RQ;
    }

    return DICOMCommand::Unknown;
}

bool DICOMPACSGuard::inspect_dicom_packet(const uint8_t* pdu_data, size_t size, std::string& out_anomaly) {
    if (!pdu_data || size < 6) return false;

    // PDU Size integrity check
    uint32_t pdu_len = 0;
    std::memcpy(&pdu_len, pdu_data + 2, 4);
    pdu_len = __builtin_bswap32(pdu_len);

    // Buffer overflow attempt in hospital PACS network
    if (pdu_len > 67108864) { // 64 MB maximum allowable medical image frame
        out_anomaly = "Excessive DICOM PDU length declaration (>64MB); possible heap overflow attempt";
        return true;
    }

    // Check for abnormal PDU Type
    uint8_t pdu_type = pdu_data[0];
    if (pdu_type > 0x07 && pdu_type != 0xFF) {
        out_anomaly = "Invalid DICOM PDU Type byte: " + std::to_string(static_cast<int>(pdu_type));
        return true;
    }

    return false;
}

} // namespace sentinel::modules::iot_sec