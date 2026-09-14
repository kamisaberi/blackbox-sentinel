#include "behavior_matrix.hpp"

namespace sentinel::modules::ueba {

void BehaviorMatrix::update_user(const std::string& user_id, double bytes, bool is_off_hours) {
    std::lock_guard<std::mutex> lock(matrix_mutex_);
    auto& p = profiles_[user_id];
    p.user_id = user_id;
    p.total_logins++;
    if (is_off_hours) {
        p.off_hours_logins++;
    }
    p.total_bytes_transferred += bytes;
    p.mean_packet_size = (p.total_bytes_transferred / static_cast<double>(p.total_logins));
}

UserProfile BehaviorMatrix::get_profile(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(matrix_mutex_);
    auto it = profiles_.find(user_id);
    if (it != profiles_.end()) {
        return it->second;
    }
    return UserProfile{user_id, 0, 0, 0.0, 0.0, 0.0f};
}

size_t BehaviorMatrix::active_user_count() {
    std::lock_guard<std::mutex> lock(matrix_mutex_);
    return profiles_.size();
}

} // namespace sentinel::modules::ueba