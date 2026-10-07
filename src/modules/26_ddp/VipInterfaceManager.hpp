#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>

namespace sentinel::deception {

struct DecoyVipEntry {
    std::string vip_address;
    std::string interface_name;
    uint8_t cidr_mask;
    std::string decoy_profile; // e.g., "SIEMENS_S7_300", "SCHNEIDER_MODBUS"
};

class VipInterfaceManager {
public:
    static VipInterfaceManager& instance() {
        static VipInterfaceManager inst;
        return inst;
    }

    // Binds a secondary VIP to the network interface using iproute2 commands
    bool bind_vip(const std::string& interface_name, 
                  const std::string& vip_address, 
                  uint8_t cidr_mask = 24, 
                  const std::string& decoy_profile = "GENERIC_HONEYPOT");

    // Unbinds a VIP from the interface
    bool unbind_vip(const std::string& vip_address);

    // Unbinds all active deception VIPs upon daemon shutdown
    void unbind_all();

    std::vector<DecoyVipEntry> list_active_vips() const;

private:
    VipInterfaceManager() = default;
    ~VipInterfaceManager() { unbind_all(); }

    mutable std::mutex mutex_;
    std::vector<DecoyVipEntry> active_vips_;
};

} // namespace sentinel::deception