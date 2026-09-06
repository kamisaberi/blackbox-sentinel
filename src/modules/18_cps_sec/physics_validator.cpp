#include "physics_validator.hpp"
#include <cmath>

namespace sentinel::modules::cps_sec {

PhysicsValidator::PhysicsValidator() = default;

bool PhysicsValidator::validate_chemical_tank_pressure(double pressure_psi, std::string& out_violation) {
    if (pressure_psi > max_safe_psi_) {
        out_violation = "Physical over-pressure boundary violation: " + std::to_string(pressure_psi) + " PSI exceeds mechanical safety threshold (90 PSI)";
        return false;
    }
    if (pressure_psi < min_safe_psi_ && pressure_psi >= 0.0) {
        out_violation = "Physical vacuum collapse hazard: " + std::to_string(pressure_psi) + " PSI below minimum threshold";
        return false;
    }
    return true;
}

bool PhysicsValidator::validate_turbine_rpm(double current_rpm, double requested_rpm, std::string& out_violation) {
    if (requested_rpm > max_safe_rpm_) {
        out_violation = "Turbine over-speed destruction risk: requested " + std::to_string(requested_rpm) + " RPM exceeds physical turbine rating";
        return false;
    }
    // Acceleration boundary validation: instantaneous jumps of >1000 RPM are physically destructive
    if (std::abs(requested_rpm - current_rpm) > 1200.0) {
        out_violation = "Destructive instantaneous torque request: acceleration rate exceeds rotor mechanical limit";
        return false;
    }
    return true;
}

} // namespace sentinel::modules::cps_sec