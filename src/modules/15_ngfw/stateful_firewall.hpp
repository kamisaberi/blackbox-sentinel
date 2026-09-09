#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>
#include <chrono>

namespace sentinel::modules::ngfw {

enum class TCPState {
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED
};

struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port;
    }
};

struct FlowKeyHasher {
    size_t operator()(const FlowKey& k) const {
        return std::hash<std::string>{}(k.src_ip + k.dst_ip) ^ (k.src_port << 16 | k.dst_port);
    }
};

class StatefulFirewall {
public:
    StatefulFirewall() = default;
    ~StatefulFirewall() = default;

    bool track_packet(const FlowKey& key, bool syn, bool ack, bool fin, bool rst, std::string& out_anomaly);

private:
    std::unordered_map<FlowKey, TCPState, FlowKeyHasher> connections_;
    std::mutex conntrack_mutex_;
};

} // namespace sentinel::modules::ngfw