#pragma once

#include <cstdint>
#include <string>

namespace sentinel::modules::swg {

class OutboundProxy {
public:
    OutboundProxy() = default;
    ~OutboundProxy() = default;

    // Inspects egress ports to identify unauthorized tunneling
    bool is_unauthorized_egress(uint16_t dest_port, const std::string& dest_ip, std::string& out_reason);
};

} // namespace sentinel::modules::swg