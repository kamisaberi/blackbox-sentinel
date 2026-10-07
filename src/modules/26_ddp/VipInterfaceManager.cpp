#include "VipInterfaceManager.hpp"
#include <cstdlib>
#include <sstream>
#include <iostream>

namespace sentinel::deception {

bool VipInterfaceManager::bind_vip(const std::string& interface_name, 
                                  const std::string& vip_address, 
                                  uint8_t cidr_mask, 
                                  const std::string& decoy_profile) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if already bound
    for (const auto& entry : active_vips_) {
        if (entry.vip_address == vip_address) return true;
    }

    // Execute Linux network configuration
    std::ostringstream cmd;
    cmd << "ip addr add " << vip_address << "/" << static_cast<int>(cidr_mask)
        << " dev " << interface_name << " label " << interface_name << ":ddp 2>/dev/null";

    int ret = std::system(cmd.str().c_str());
    if (ret == 0) {
        active_vips_.push_back({
            .vip_address = vip_address,
            .interface_name = interface_name,
            .cidr_mask = cidr_mask,
            .decoy_profile = decoy_profile
        });
        std::cout << "[VipManager] Bound secondary VIP [" << vip_address << "] on " 
                  << interface_name << " for decoy profile: " << decoy_profile << std::endl;
        return true;
    }

    return false;
}

bool VipInterfaceManager::unbind_vip(const std::string& vip_address) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = active_vips_.begin(); it != active_vips_.end(); ++it) {
        if (it->vip_address == vip_address) {
            std::ostringstream cmd;
            cmd << "ip addr del " << it->vip_address << "/" << static_cast<int>(it->cidr_mask)
                << " dev " << it->interface_name << " 2>/dev/null";
            std::system(cmd.str().c_str());

            std::cout << "[VipManager] Unbound secondary VIP [" << vip_address << "]" << std::endl;
            active_vips_.erase(it);
            return true;
        }
    }
    return false;
}

void VipInterfaceManager::unbind_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : active_vips_) {
        std::ostringstream cmd;
        cmd << "ip addr del " << entry.vip_address << "/" << static_cast<int>(entry.cidr_mask)
            << " dev " << entry.interface_name << " 2>/dev/null";
        std::system(cmd.str().c_str());
    }
    active_vips_.clear();
}

std::vector<DecoyVipEntry> VipInterfaceManager::list_active_vips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_vips_;
}

} // namespace sentinel::deception