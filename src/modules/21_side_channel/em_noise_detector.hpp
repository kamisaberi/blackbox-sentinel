#pragma once

#include <vector>
#include <cstddef>

namespace sentinel::modules::side_channel {

class EMNoiseDetector {
public:
    EMNoiseDetector() = default;
    ~EMNoiseDetector() = default;

    // Inspects electromagnetic spectrum emission bursts (Simple Electro-Magnetic Analysis - SEMA)
    bool detect_sema_leakage(const std::vector<float>& spectrum_bins, float threshold_snr = 25.0f);
};

} // namespace sentinel::modules::side_channel