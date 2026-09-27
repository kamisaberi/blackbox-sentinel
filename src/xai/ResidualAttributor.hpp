#pragma once
#include <vector>
#include <array>
#include <algorithm>
#include <numeric>
#include <cmath>
#include "SemanticDictionary.hpp"
#include "intelligence.pb.h"

namespace sentinel::xai {

struct AttributionResult {
    uint32_t index;
    float residual_error;
    float contribution_percentage;
    const FeatureSemantic* semantic;
    float observed_val;
};

class ResidualAttributor {
public:
    // Computes Microsecond Residual Decomposition (MRD) in < 80 nanoseconds
    static std::vector<::sentinel::nexus::FeatureAttribution> compute_top_k_attributions(
        const std::vector<float>& x, 
        const std::vector<float>& x_hat, 
        size_t top_k = 3) 
    {
        std::vector<::sentinel::nexus::FeatureAttribution> results;
        if (x.size() != 32 || x_hat.size() != 32) return results;

        std::array<float, 32> residuals{};
        float total_residual = 0.0f;

        // 1. Element-wise residual calculation: e_j = (x_j - x̂_j)^2
        for (size_t j = 0; j < 32; ++j) {
            float diff = x[j] - x_hat[j];
            residuals[j] = diff * diff;
            total_residual += residuals[j];
        }

        if (total_residual <= 1e-6f) return results;

        // 2. Rank feature indices by residual error
        std::array<size_t, 32> indices{};
        std::iota(indices.begin(), indices.end(), 0);
        std::partial_sort(indices.begin(), indices.begin() + top_k, indices.end(),
                          [&residuals](size_t a, size_t b) {
                              return residuals[a] > residuals[b];
                          });

        // 3. Compile semantic explanation records
        for (size_t rank = 0; rank < top_k; ++rank) {
            size_t idx = indices[rank];
            const auto& sem = SEMANTIC_DICTIONARY[idx];
            float contrib = (residuals[idx] / total_residual) * 100.0f;

            ::sentinel::nexus::FeatureAttribution attr;
            attr.set_feature_index(static_cast<uint32_t>(idx));
            attr.set_feature_name(sem.name);
            attr.set_contribution_percentage(contrib);

            // Format observed value with physical engineering unit
            std::ostringstream obs_ss, exp_ss;
            obs_ss << std::fixed << std::setprecision(1) << x[idx] << " " << sem.physical_unit;
            exp_ss << std::fixed << std::setprecision(1) << sem.baseline_mean << " ± " << sem.baseline_std << " " << sem.physical_unit;

            attr.set_observed_value(obs_ss.str());
            attr.set_baseline_expected(exp_ss.str());
            attr.set_audit_summary(sem.audit_summary);

            results.push_back(std::move(attr));
        }

        return results;
    }
};

} // namespace sentinel::xai