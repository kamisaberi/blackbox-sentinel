#pragma once

#include <cstdint>
#include <cstddef>

namespace sentinel::modules::epp_ngav {

class FileEntropyCalculator {
public:
    FileEntropyCalculator() = default;
    ~FileEntropyCalculator() = default;

    // Computes Shannon Entropy: H = -sum(P(x) * log2(P(x)))
    double calculate_entropy(const uint8_t* data, size_t size);
    bool is_ransomware_encrypted(double entropy);
};

} // namespace sentinel::modules::epp_ngav