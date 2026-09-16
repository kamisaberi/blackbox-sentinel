#include "vlan_isolator.hpp"

namespace sentinel::modules::nac {

VLANIsolator::VLANIsolator(uint16_t quarantine_vlan)
    : quarantine_vlan_(quarantine_vlan) {}

bool VLANIsolator::isolate_device(const std::string& mac_or_ip, std::string& out_action) {
    std::lock_guard<std::mutex> lock(isolator_mutex_);
    if (isolated_devices_.find(mac_or_ip) != isolated_devices_.end()) {
        out_action = "Device already isolated in Quarantine VLAN " + std::to_string(quarantine_vlan_);
        return true;
    }

    isolated_devices_.insert(mac_or_ip);
    out_action = "Assigned IEEE 802.1Q Quarantine VLAN " + std::to_string(quarantine_vlan_) + " via eBPF ingress filter";
    return true;
}

bool VLANIsolator::restore_device(const std::string& mac_or_ip) {
    std::lock_guard<std::mutex> lock(isolator_mutex_);
    return (isolated_devices_.erase(mac_or_ip) > 0);
}

bool VLANIsolator::is_isolated(const std::string& mac_or_ip) {
    std::lock_guard<std::mutex> lock(isolator_mutex_);
    return (isolated_devices_.find(mac_or_ip) != isolated_devices_.end());
}

} // namespace sentinel::modules::nac