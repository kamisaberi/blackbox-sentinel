#include "dpi_engine.hpp"
#include <cstring>

namespace sentinel::modules::ngfw {

std::string DPIEngine::protocol_to_string(AppProtocol proto) const {
    switch (proto) {
        case AppProtocol::HTTP:        return "HTTP";
        case AppProtocol::TLS_HTTPS:   return "TLS/HTTPS";
        case AppProtocol::SSH:         return "SSH";
        case AppProtocol::DNS:         return "DNS";
        case AppProtocol::ModbusTCP:   return "Modbus-TCP";
        case AppProtocol::DNP3:        return "DNP3";
        case AppProtocol::BitTorrent:  return "BitTorrent";
        case AppProtocol::WireGuard:   return "WireGuard";
        default:                       return "Unknown Protocol";
    }
}

AppProtocol DPIEngine::inspect_payload(const uint8_t* payload, size_t size, uint16_t dest_port) {
    if (!payload || size == 0) return AppProtocol::Unknown;

    // TLS Handshake signature: 0x16 0x03 (TLS Record Layer)
    if (size >= 3 && payload[0] == 0x16 && payload[1] == 0x03) {
        return AppProtocol::TLS_HTTPS;
    }

    // SSH Identification banner: "SSH-"
    if (size >= 4 && payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-') {
        return AppProtocol::SSH;
    }

    // HTTP Verbs
    if (size >= 4 && (std::memcmp(payload, "GET ", 4) == 0 ||
                      std::memcmp(payload, "POST", 4) == 0 ||
                      std::memcmp(payload, "HEAD", 4) == 0)) {
        return AppProtocol::HTTP;
    }

    // SCADA Modbus TCP (Port 502 or protocol ID 0x0000 in MBAP header)
    if (dest_port == 502 || (size >= 4 && payload[2] == 0x00 && payload[3] == 0x00)) {
        return AppProtocol::ModbusTCP;
    }

    // DNP3 Start Bytes: 0x05 0x64
    if (dest_port == 20000 || (size >= 2 && payload[0] == 0x05 && payload[1] == 0x64)) {
        return AppProtocol::DNP3;
    }

    // BitTorrent Handshake: \x13BitTorrent protocol
    if (size >= 20 && payload[0] == 0x13 && std::memcmp(payload + 1, "BitTorrent", 10) == 0) {
        return AppProtocol::BitTorrent;
    }

    return AppProtocol::Unknown;
}

} // namespace sentinel::modules::ngfw