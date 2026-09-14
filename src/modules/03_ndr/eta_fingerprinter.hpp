#pragma once

#include <vector>
#include <cstddef>

namespace sentinel::modules::ndr {

class ETAFingerprinter {
public:
    ETAFingerprinter() = default;
    ~ETAFingerprinter() = default;

    // Analyzes packet length sequences and arrival timing without TLS decryption
    float compute_malware_probability(const std::vector<float>& packet_sequence);
};

} // namespace sentinel::modules::ndr