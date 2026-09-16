#include "device_fingerprinter.hpp"
#include <algorithm>

namespace sentinel::modules::nac {

DeviceFingerprinter::DeviceFingerprinter() = default;

std::string DeviceFingerprinter::category_to_string(DeviceCategory cat) const {
    switch (cat) {
        case DeviceCategory::CorporateWorkstation: return "Corporate Workstation";
        case DeviceCategory::ServerInfrastructure: return "Server Infrastructure";
        case DeviceCategory::IndustrialPLC:        return "Industrial PLC";
        case DeviceCategory::MedicalEquipment:     return "Medical Equipment";
        case DeviceCategory::IoTDevice:            return "IoT Device";
        case DeviceCategory::RogueDevice:          return "Rogue Unauthorized Device";
        default:                                   return "Unknown Device";
    }
}

DeviceFingerprint DeviceFingerprinter::analyze_handshake(const std::string& mac, const std::string& hostname, uint8_t ttl) {
    std::lock_guard<std::mutex> lock(registry_mutex_);

    DeviceFingerprint fp;
    fp.mac_address = mac;
    fp.hostname = hostname;
    fp.initial_ttl = ttl;

    // MAC OUI Prefix Heuristics
    std::string prefix = mac.substr(0, std::min(mac.size(), static_cast<size_t>(8)));
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

    if (prefix == "00:1B:1B" || prefix == "00:0E:8C") {
        fp.vendor_oui = "Siemens Industrial";
        fp.category = DeviceCategory::IndustrialPLC;
        fp.trust_score = 0.90f;
    } else if (prefix == "00:50:56" || prefix == "00:0C:29") {
        fp.vendor_oui = "VMware Virtual Host";
        fp.category = DeviceCategory::ServerInfrastructure;
        fp.trust_score = 0.85f;
    } else if (prefix == "B8:27:EB" || prefix == "DC:A6:32") {
        fp.vendor_oui = "Raspberry Pi Foundation";
        fp.category = DeviceCategory::IoTDevice;
        fp.trust_score = 0.40f;
    } else {
        fp.vendor_oui = "Generic / Unrecognized";
        fp.category = (ttl == 128) ? DeviceCategory::CorporateWorkstation : DeviceCategory::Unknown;
        fp.trust_score = 0.50f;
    }

    if (hostname.find("kali") != std::string::npos || hostname.find("exploit") != std::string::npos) {
        fp.category = DeviceCategory::RogueDevice;
        fp.trust_score = 0.05f;
    }

    registry_[mac] = fp;
    return fp;
}

} // namespace sentinel::modules::nac