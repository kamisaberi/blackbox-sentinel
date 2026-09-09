#include "login_velocity.hpp"
#include <algorithm>

namespace sentinel::modules::ato {

bool LoginVelocityTracker::check_velocity(const std::string& username, const std::string& ip_address, bool is_failure) {
    if (!is_failure) return false;

    std::lock_guard<std::mutex> lock(tracker_mutex_);
    auto now = std::chrono::steady_clock::now();

    auto clean_and_count = [&](std::vector<std::chrono::steady_clock::time_point>& timestamps, std::chrono::seconds window) {
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                [&](const auto& tp) { return (now - tp) > window; }),
            timestamps.end()
        );
        timestamps.push_back(now);
        return timestamps.size();
    };

    size_t ip_count = clean_and_count(ip_attempts_[ip_address], std::chrono::seconds(60));
    size_t user_count = clean_and_count(user_attempts_[username], std::chrono::seconds(300));

    // > 10 failed logins from 1 IP in 1 minute -> Credential Stuffing
    if (ip_count > 10) return true;

    // > 5 failed logins for 1 user account in 5 minutes -> Password Spraying / Brute Force
    if (user_count > 5) return true;

    return false;
}

} // namespace sentinel::modules::ato