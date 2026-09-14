#pragma once

#include <string>
#include <unordered_set>
#include <mutex>

namespace sentinel::modules::ids_ips {

class XDPPacketDropper {
public:
    XDPPacketDropper() = default;
    ~XDPPacketDropper() = default;

    bool enforce_drop(const std::string& ip_address);
    bool remove_drop(const std::string& ip_address);
    bool is_dropped(const std::string& ip_address);
    size_t active_drop_count();

private:
    std::unordered_set<std::string> dropped_ips_;
    std::mutex drop_mutex_;
};

} // namespace sentinel::modules::ids_ips