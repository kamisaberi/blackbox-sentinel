#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace sentinel::modules::ueba {

struct UserProfile {
    std::string user_id;
    uint64_t total_logins{0};
    uint64_t off_hours_logins{0};
    double mean_packet_size{0.0};
    double total_bytes_transferred{0.0};
    float risk_score{0.0f};
};

class BehaviorMatrix {
public:
    BehaviorMatrix() = default;
    ~BehaviorMatrix() = default;

    void update_user(const std::string& user_id, double bytes, bool is_off_hours);
    UserProfile get_profile(const std::string& user_id);
    size_t active_user_count();

private:
    std::unordered_map<std::string, UserProfile> profiles_;
    std::mutex matrix_mutex_;
};

} // namespace sentinel::modules::ueba