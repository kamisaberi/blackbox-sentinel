#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>

namespace sentinel::modules::ato {

class LoginVelocityTracker {
public:
    LoginVelocityTracker() = default;
    ~LoginVelocityTracker() = default;

    // Tracks authentication velocity per user and per source IP
    bool check_velocity(const std::string& username, const std::string& ip_address, bool is_failure);

private:
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> user_attempts_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> ip_attempts_;
    std::mutex tracker_mutex_;
};

} // namespace sentinel::modules::ato