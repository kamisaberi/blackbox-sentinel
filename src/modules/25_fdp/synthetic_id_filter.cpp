#include "synthetic_id_filter.hpp"

namespace sentinel::modules::fdp {

float SyntheticIDFilter::evaluate_synthetic_risk(const std::vector<float>& id_features) {
    if (id_features.size() < 4) {
        return 0.10f; // Baseline
    }

    float account_age_norm = id_features[0];     // 0 = Brand new account, 1 = Mature
    float velocity_norm    = id_features[1];     // High transaction frequency
    float ssn_entropy_norm = id_features[2];     // Unusual SSN/Tax number pattern
    float ip_reputation    = id_features[3];     // Proxy / VPN exit node indicator

    // Formula: New account + high velocity + high IP proxy score
    float risk = (1.0f - account_age_norm) * 0.40f + 
                 velocity_norm * 0.30f + 
                 ip_reputation * 0.30f;

    if (ssn_entropy_norm > 0.85f) {
        risk += 0.20f;
    }

    return std::min(1.0f, risk);
}

} // namespace sentinel::modules::fdp