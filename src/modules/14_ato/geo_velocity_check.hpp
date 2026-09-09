#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <mutex>

namespace sentinel::modules::ato {

struct GeoLocation {
    double latitude;
    double longitude;
    std::chrono::system_clock::time_point timestamp;
};

class GeoVelocityCheck {
public:
    GeoVelocityCheck() = default;
    ~GeoVelocityCheck() = default;

    // Uses the Haversine formula to compute travel speed between logins
    bool is_impossible_travel(const std::string& user_id, double lat, double lon, double& out_speed_kmh);

private:
    double haversine_distance_km(double lat1, double lon1, double lat2, double lon2);

    std::unordered_map<std::string, GeoLocation> last_locations_;
    std::mutex geo_mutex_;
};

} // namespace sentinel::modules::ato