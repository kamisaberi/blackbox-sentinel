#pragma once
#include <string>
#include <unordered_set>
#include <mutex>

namespace sentinel::nexus_client {

class SimulationModeController {
public:
    static SimulationModeController& instance() {
        static SimulationModeController inst;
        return inst;
    }

    void enable_simulation_mode(bool enable);
    bool is_simulation_mode_active() const;

    // Registers an authorized IP as an active Breach and Attack Simulation (BAS) generator
    void register_authorized_simulator_ip(const std::string& ip_address);
    bool is_simulated_traffic(const std::string& source_ip) const;

    // Evaluates whether an alert should be suppressed from emergency escalation
    bool should_suppress_panic_alarm(const std::string& source_ip) const;

private:
    SimulationModeController();

    mutable std::mutex mutex_;
    bool simulation_mode_active_{false};
    std::unordered_set<std::string> authorized_simulator_ips_;
};

} // namespace sentinel::nexus_client