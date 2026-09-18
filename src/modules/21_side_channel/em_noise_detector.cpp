#include "em_noise_detector.hpp"
#include <algorithm>
#include <numeric>

namespace sentinel::modules::side_channel {

bool EMNoiseDetector::detect_sema_leakage(const std::vector<float>& bins, float threshold_snr) {
    if (bins.size() < 16) return false;

    float max_peak = *std::max_element(bins.begin(), bins.end());
    float sum = std::accumulate(bins.begin(), bins.end(), 0.0f);
    float noise_floor = (sum - max_peak) / static_cast<float>(bins.size() - 1);

    if (noise_floor > 0.0001f) {
        float snr = 10.0f * std::log10(max_peak / noise_floor);
        if (snr > threshold_snr) {
            return true;
        }
    }

    return false;
}

} // namespace sentinel::modules::side_channel