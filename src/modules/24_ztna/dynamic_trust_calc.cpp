#include "dynamic_trust_calc.hpp"
#include <algorithm>

namespace sentinel::modules::ztna {

uint32_t DynamicTrustCalculator::evaluate_trust(const std::string& device_id, float observed_risk) {
    std::lock_guard<std::mutex> lock(trust_mutex_);
    auto now = std::chrono::system_clock::now();
    auto& p = profiles_[device_id];
    p.device_id = device_id;
    p.last_updated = now;

    // Decay trust score based on observed risk factor
    if (observed_risk > 0.80f) {
        p.anomaly_count += 3;
        p.trust_score = (p.trust_score >= 40) ? (p.trust_score - 40) : 0;
    } else if (observed_risk > 0.50f) {
        p.anomaly_count += 1;
        p.trust_score = (p.trust_score >= 15) ? (p.trust_score - 15) : 0;
    } else {
        // Slow recovery of trust on clean telemetry
        if (p.trust_score < 100) {
            p.trust_score += 1;
        }
    }

    return p.trust_score;
}

uint32_t DynamicTrustCalculator::get_score(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(trust_mutex_);
    auto it = profiles_.find(device_id);
    if (it != profiles_.end()) {
        return it->second.trust_score;
    }
    return 100; // Default new device baseline
}

} // namespace sentinel::modules::ztna