#pragma once

#include "behavior_matrix.hpp"

namespace sentinel::modules::ueba {

class BaselineScorer {
public:
    BaselineScorer() = default;
    ~BaselineScorer() = default;

    float calculate_anomaly(const UserProfile& profile, double incoming_bytes, bool is_off_hours);
};

} // namespace sentinel::modules::ueba