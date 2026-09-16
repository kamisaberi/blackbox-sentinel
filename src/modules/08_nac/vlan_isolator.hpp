#pragma once

#include <string>
#include <cstdint>
#include <unordered_set>
#include <mutex>

namespace sentinel::modules::nac {

class VLANIsolator {
public:
    explicit VLANIsolator(uint16_t quarantine_vlan = 999);
    ~VLANIsolator() = default;

    bool isolate_device(const std::string& mac_or_ip, std::string& out_action);
    bool restore_device(const std::string& mac_or_ip);
    bool is_isolated(const std::string& mac_or_ip);

private:
    uint16_t quarantine_vlan_;
    std::unordered_set<std::string> isolated_devices_;
    std::mutex isolator_mutex_;
};

} // namespace sentinel::modules::nac