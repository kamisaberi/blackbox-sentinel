#include "geo_velocity_check.hpp"
#include <cmath>

namespace sentinel::modules::ato {

constexpr double EARTH_RADIUS_KM = 6371.0;
constexpr double DEG_TO_RAD = M_PI / 180.0;

double GeoVelocityCheck::haversine_distance_km(double lat1, double lon1, double lat2, double lon2) {
    double dlat = (lat2 - lat1) * DEG_TO_RAD;
    double dlon = (lon2 - lon1) * DEG_TO_RAD;

    double a = std::sin(dlat / 2.0) * std::sin(dlat / 2.0) +
               std::cos(lat1 * DEG_TO_RAD) * std::cos(lat2 * DEG_TO_RAD) *
               std::sin(dlon / 2.0) * std::sin(dlon / 2.0);
    double c = 2.0 * std::atan2(std::sqrt(a), std::sqrt(1.0 - a));
    return EARTH_RADIUS_KM * c;
}

bool GeoVelocityCheck::is_impossible_travel(const std::string& user_id, double lat, double lon, double& out_speed_kmh) {
    std::lock_guard<std::mutex> lock(geo_mutex_);
    auto now = std::chrono::system_clock::now();
    out_speed_kmh = 0.0;

    auto it = last_locations_.find(user_id);
    if (it != last_locations_.end()) {
        const auto& prev = it->second;
        double distance_km = haversine_distance_km(prev.latitude, prev.longitude, lat, lon);
        double elapsed_hours = std::chrono::duration<double, std::ratio<3600>>(now - prev.timestamp).count();

        if (elapsed_hours > 0.001) {
            out_speed_kmh = distance_km / elapsed_hours;
            // Commercial airplane speeds rarely exceed 950 km/h
            if (out_speed_kmh > 950.0 && distance_km > 500.0) {
                last_locations_[user_id] = {lat, lon, now};
                return true; // Impossible travel detected
            }
        }
    }

    last_locations_[user_id] = {lat, lon, now};
    return false;
}

} // namespace sentinel::modules::ato