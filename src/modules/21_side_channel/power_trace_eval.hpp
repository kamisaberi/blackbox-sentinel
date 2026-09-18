#pragma once

#include <vector>
#include <cstddef>

namespace sentinel::modules::side_channel {

class PowerTraceEvaluator {
public:
    PowerTraceEvaluator() = default;
    ~PowerTraceEvaluator() = default;

    // Detects Differential Power Analysis (DPA) or fault injection spikes
    bool detect_dpa_anomaly(const std::vector<float>& power_mw_samples, float& out_variance);
};

} // namespace sentinel::modules::side_channel