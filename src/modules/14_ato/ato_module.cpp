#include "ato_module.hpp"
#include <iostream>

namespace sentinel::modules::ato {

AtoModule::AtoModule()
    : velocity_tracker_(std::make_unique<LoginVelocityTracker>()),
      geo_check_(std::make_unique<GeoVelocityCheck>()) {}

bool AtoModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 14] ATO Account Takeover Defense Engine initialized." << std::endl;
    return true;
}

bool AtoModule::start() {
    running_ = true;
    std::cout << "[Module 14] ATO Account Takeover Defense Engine started." << std::endl;
    return true;
}

void AtoModule::stop() {
    running_ = false;
    std::cout << "[Module 14] ATO Account Takeover Defense Engine stopped." << std::endl;
}

void AtoModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Check failed login velocity in authentication logs
    if (event.description.find("Failed password") != std::string::npos) {
        if (velocity_tracker_->check_velocity("admin", event.source_ip, true)) {
            event.anomaly_score = 0.96f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::EBPFBlockIP;
            event.description += " [ATO Alert: High-Velocity Credential Stuffing / Brute Force]";
        }
    }

    // Check impossible travel if GPS coordinates are embedded in event features
    if (event.features.size() >= 2) {
        double lat = event.features[0] * 90.0;
        double lon = event.features[1] * 180.0;
        double speed_kmh = 0.0;
        if (geo_check_->is_impossible_travel(event.source_ip, lat, lon, speed_kmh)) {
            event.anomaly_score = 0.94f;
            event.level = blackbox::ThreatLevel::High;
            event.description += " [ATO Alert: Impossible Travel Velocity (" + std::to_string(static_cast<int>(speed_kmh)) + " km/h)]";
        }
    }
}

bool AtoModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ato