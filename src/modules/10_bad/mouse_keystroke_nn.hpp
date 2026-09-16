#pragma once

#include <vector>
#include <cstddef>

namespace sentinel::modules::bad {

class MouseKeystrokeNN {
public:
    MouseKeystrokeNN() = default;
    ~MouseKeystrokeNN() = default;

    // Computes biological variance vs programmatic linearity in interaction streams
    float evaluate_bot_probability(const std::vector<float>& kinematics_trajectory);
};

} // namespace sentinel::modules::bad