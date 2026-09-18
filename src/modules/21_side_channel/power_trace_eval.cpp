#include "power_trace_eval.hpp"
#include <numeric>
#include <cmath>

namespace sentinel::modules::side_channel {

bool PowerTraceEvaluator::detect_dpa_anomaly(const std::vector<float>& samples, float& out_variance) {
    if (samples.size() < 10) {
        out_variance = 0.0f;
        return false;
    }

    float sum = std::accumulate(samples.begin(), samples.end(), 0.0f);
    float mean = sum / static_cast<float>(samples.size());

    float sq_sum = 0.0f;
    for (float val : samples) {
        sq_sum += (val - mean) * (val - mean);
    }
    out_variance = sq_sum / static_cast<float>(samples.size());

    // Abrupt, synchronized periodic power oscillations indicate cryptographic trace capture
    if (out_variance > 500.0f) {
        return true;
    }

    return false;
}

} // namespace sentinel::modules::side_channel