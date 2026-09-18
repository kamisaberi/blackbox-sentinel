#pragma once

#include <string>
#include <cstdint>

namespace sentinel::modules::ddp {

class DecoyPLCTrap {
public:
    DecoyPLCTrap() = default;
    ~DecoyPLCTrap() = default;

    // Emulates virtual Siemens S7-1500 PLC responses on decoy secondary IPs
    bool handle_probe(uint16_t port, const std::string& payload, std::string& out_alert);
};

} // namespace sentinel::modules::ddp