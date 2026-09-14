#include "xdp_packet_dropper.hpp"
#include <iostream>

namespace sentinel::modules::ids_ips {

bool XDPPacketDropper::enforce_drop(const std::string& ip_address) {
    if (ip_address.empty()) return false;
    std::lock_guard<std::mutex> lock(drop_mutex_);
    
    if (dropped_ips_.find(ip_address) != dropped_ips_.end()) {
        return true;
    }

    dropped_ips_.insert(ip_address);
    std::cout << "[IDS/IPS Kernel Hook] Hardware XDP drop registered for IP: " << ip_address << std::endl;
    return true;
}

bool XDPPacketDropper::remove_drop(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(drop_mutex_);
    return (dropped_ips_.erase(ip_address) > 0);
}

bool XDPPacketDropper::is_dropped(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(drop_mutex_);
    return (dropped_ips_.find(ip_address) != dropped_ips_.end());
}

size_t XDPPacketDropper::active_drop_count() {
    std::lock_guard<std::mutex> lock(drop_mutex_);
    return dropped_ips_.size();
}

} // namespace sentinel::modules::ids_ips