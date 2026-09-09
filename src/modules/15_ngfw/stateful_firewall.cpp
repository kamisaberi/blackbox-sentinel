#include "stateful_firewall.hpp"

namespace sentinel::modules::ngfw {

bool StatefulFirewall::track_packet(const FlowKey& key, bool syn, bool ack, bool fin, bool rst, std::string& out_anomaly) {
    std::lock_guard<std::mutex> lock(conntrack_mutex_);

    // Check for invalid TCP flag combinations (XMAS scan, NULL scan)
    if (!syn && !ack && !fin && !rst) {
        out_anomaly = "TCP NULL scan detected (no flags set)";
        return false;
    }

    if (syn && fin) {
        out_anomaly = "SYN-FIN illegal TCP flag combination detected";
        return false;
    }

    auto it = connections_.find(key);
    if (it == connections_.end()) {
        if (syn && !ack) {
            connections_[key] = TCPState::SYN_SENT;
            return true; // Valid handshake start
        }
        if (ack && !syn) {
            out_anomaly = "Out-of-state ACK packet without prior SYN handshake (ACK scan)";
            return false;
        }
    } else {
        if (it->second == TCPState::SYN_SENT && ack) {
            it->second = TCPState::ESTABLISHED;
            return true;
        }
        if (fin || rst) {
            connections_.erase(it);
            return true;
        }
    }

    return true;
}

} // namespace sentinel::modules::ngfw