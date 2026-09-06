#pragma once

#include <string>

namespace sentinel::modules::cps_sec {

class PhysicsValidator {
public:
    PhysicsValidator();
    ~PhysicsValidator() = default;

    // Verifies physical law boundaries (pressure, temperature, valve flow, turbine RPM)
    bool validate_chemical_tank_pressure(double pressure_psi, std::string& out_violation);
    bool validate_turbine_rpm(double current_rpm, double requested_rpm, std::string& out_violation);

private:
    double min_safe_psi_{5.0};
    double max_safe_psi_{90.0};
    double max_safe_rpm_{3600.0};
};

} // namespace sentinel::modules::cps_sec