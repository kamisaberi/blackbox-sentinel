#pragma once

#include <vector>
#include <string>

namespace sentinel::modules::fdp {

class SyntheticIDFilter {
public:
    SyntheticIDFilter() = default;
    ~SyntheticIDFilter() = default;

    // Evaluates identity features (account age, SSN entropy, velocity) for synthetic identity fraud
    float evaluate_synthetic_risk(const std::vector<float>& id_features);
};

} // namespace sentinel::modules::fdp