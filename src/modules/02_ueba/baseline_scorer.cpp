#include "baseline_scorer.hpp"
#include <algorithm>
#include <cmath>

namespace sentinel::modules::ueba {

float BaselineScorer::calculate_anomaly(const UserProfile& profile, double incoming_bytes, bool is_off_hours) {
    if (profile.total_logins < 5) {
        return 0.10f; // Insufficient history baseline
    }

    float score = 0.0f;

    // Check off-hours deviation ratio
    double off_hours_ratio = static_cast<double>(profile.off_hours_logins) / static_cast<double>(profile.total_logins);
    if (is_off_hours && off_hours_ratio < 0.10) {
        score += 0.45f;
    }

    // Check volume deviation
    if (profile.mean_packet_size > 0.0) {
        double ratio = incoming_bytes / profile.mean_packet_size;
        if (ratio > 5.0) {
            score += 0.40f;
        }
    }

    return std::clamp(score, 0.0f, 1.0f);
}

} // namespace sentinel::modules::ueba