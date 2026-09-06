#include "outbound_proxy.hpp"

namespace sentinel::modules::swg {

bool OutboundProxy::is_unauthorized_egress(uint16_t dest_port, const std::string& dest_ip, std::string& out_reason) {
    (void)dest_ip;

    // Detect egress tunneling over non-standard ports (e.g. SOCKS5 proxy on 1080, Tor on 9050)
    if (dest_port == 1080 || dest_port == 9050 || dest_port == 9051) {
        out_reason = "Unauthorized outbound proxy / Tor routing attempt on port " + std::to_string(dest_port);
        return true;
    }

    // Direct SSH egress from restricted corporate subnets
    if (dest_port == 2222 || dest_port == 4444) {
        out_reason = "High-risk reverse shell outbound egress port " + std::to_string(dest_port);
        return true;
    }

    return false;
}

} // namespace sentinel::modules::swg