#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>

namespace sentinel::modules::nac {

enum class DeviceCategory {
    Unknown,
    CorporateWorkstation,
    ServerInfrastructure,
    IndustrialPLC,
    MedicalEquipment,
    IoTDevice,
    RogueDevice
};

struct DeviceFingerprint {
    std::string mac_address;
    std::string hostname;
    std::string vendor_oui;
    uint8_t initial_ttl{64};
    DeviceCategory category{DeviceCategory::Unknown};
    float trust_score{0.5f};
};

class DeviceFingerprinter {
public:
    DeviceFingerprinter();
    ~DeviceFingerprinter() = default;

    DeviceFingerprint analyze_handshake(const std::string& mac, const std::string& hostname, uint8_t ttl);
    std::string category_to_string(DeviceCategory cat) const;

private:
    std::unordered_map<std::string, DeviceFingerprint> registry_;
    std::mutex registry_mutex_;
};

} // namespace sentinel::modules::nac