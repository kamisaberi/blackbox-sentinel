#include "file_entropy_calc.hpp"
#include <cmath>
#include <vector>

namespace sentinel::modules::epp_ngav {

double FileEntropyCalculator::calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    std::vector<size_t> frequencies(256, 0);
    for (size_t i = 0; i < size; ++i) {
        frequencies[data[i]]++;
    }

    double entropy = 0.0;
    for (size_t count : frequencies) {
        if (count > 0) {
            double p = static_cast<double>(count) / static_cast<double>(size);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

bool FileEntropyCalculator::is_ransomware_encrypted(double entropy) {
    // Shannon entropy > 7.3 out of 8.0 indicates high randomness typical of AES/ChaCha ransomware encryption
    return (entropy >= 7.30);
}

} // namespace sentinel::modules::epp_ngav