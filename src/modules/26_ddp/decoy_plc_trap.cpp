#include "decoy_plc_trap.hpp"

namespace sentinel::modules::ddp {

bool DecoyPLCTrap::handle_probe(uint16_t port, const std::string& payload, std::string& out_alert) {
    // Intercept Modbus (502) or Siemens S7 (102) targeting decoy IP
    if (port == 502 || port == 102) {
        out_alert = "Attacker connected to Industrial Honeytrap Decoy PLC on port " + std::to_string(port);
        return true;
    }

    if (payload.find("S7COMM") != std::string::npos) {
        out_alert = "Siemens S7Comm handshake probed against Decoy Trap";
        return true;
    }

    return false;
}

} // namespace sentinel::modules::ddp