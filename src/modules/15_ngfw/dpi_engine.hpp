#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace sentinel::modules::ngfw {

enum class AppProtocol {
    Unknown,
    HTTP,
    TLS_HTTPS,
    SSH,
    DNS,
    ModbusTCP,
    DNP3,
    BitTorrent,
    WireGuard
};

class DPIEngine {
public:
    DPIEngine() = default;
    ~DPIEngine() = default;

    AppProtocol inspect_payload(const uint8_t* payload, size_t size, uint16_t dest_port);
    std::string protocol_to_string(AppProtocol proto) const;
};

} // namespace sentinel::modules::ngfw