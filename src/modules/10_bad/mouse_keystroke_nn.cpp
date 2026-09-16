#include "mouse_keystroke_nn.hpp"
#include <numeric>
#include <cmath>

namespace sentinel::modules::bad {

float MouseKeystrokeNN::evaluate_bot_probability(const std::vector<float>& trajectory) {
    if (trajectory.size() < 6) {
        return 0.10f; // Baseline
    }

    // Calculate straight-line curvature variance
    float sum_diff = 0.0f;
    for (size_t i = 1; i < trajectory.size(); ++i) {
        sum_diff += std::abs(trajectory[i] - trajectory[i - 1]);
    }
    float mean_diff = sum_diff / (trajectory.size() - 1);

    // Calculate jerk/jitter variance
    float variance = 0.0f;
    for (size_t i = 1; i < trajectory.size(); ++i) {
        float diff = std::abs(trajectory[i] - trajectory[i - 1]);
        variance += (diff - mean_diff) * (diff - mean_diff);
    }
    variance /= (trajectory.size() - 1);

    // Completely uniform movement (variance near 0) indicates automated bot scripts
    if (variance < 0.0001f) {
        return 0.98f;
    }

    // High natural entropy confirms biological human operator
    if (variance > 0.01f) {
        return 0.02f;
    }

    return 0.45f;
}

} // namespace sentinel::modules::bad