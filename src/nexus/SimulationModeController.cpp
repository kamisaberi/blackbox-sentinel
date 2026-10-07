#include "SimulationModeController.hpp"
#include <iostream>

namespace sentinel::nexus_client {

SimulationModeController::SimulationModeController() {
    // Default: Container mesh adversary IP is authorized by default
    authorized_simulator_ips_.insert("10.240.0.99");
}

void SimulationModeController::enable_simulation_mode(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    simulation_mode_active_ = enable;
    std::cout << "[SimulationController] Simulation Audit Mode: " 
              << (enable ? "\033[33mACTIVE (Alarms Suppressed)\033[0m" : "\033[32mINACTIVE (Live Defense)\033[0m") 
              << std::endl;
}

bool SimulationModeController::is_simulation_mode_active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return simulation_mode_active_;
}

void SimulationModeController::register_authorized_simulator_ip(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(mutex_);
    authorized_simulator_ips_.insert(ip_address);
}

bool SimulationModeController::is_simulated_traffic(const std::string& source_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return authorized_simulator_ips_.contains(source_ip);
}

bool SimulationModeController::should_suppress_panic_alarm(const std::string& source_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (simulation_mode_active_) return true;
    return authorized_simulator_ips_.contains(source_ip);
}

} // namespace sentinel::nexus_client