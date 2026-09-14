#include "eta_fingerprinter.hpp"
#include <numeric>
#include <cmath>

namespace sentinel::modules::ndr {

float ETAFingerprinter::compute_malware_probability(const std::vector<float>& packet_sequence) {
    if (packet_sequence.size() < 4) {
        return 0.05f; // Normal baseline
    }

    // Inspect regularity of packet length variations (C2 beaconing profile)
    float sum = std::accumulate(packet_sequence.begin(), packet_sequence.end(), 0.0f);
    float mean = sum / packet_sequence.size();

    float variance = 0.0f;
    for (float val : packet_sequence) {
        variance += (val - mean) * (val - mean);
    }
    variance /= packet_sequence.size();

    // Low variance in timing/size during persistent connections indicates automated C2 beaconing
    if (variance < 0.005f && mean > 0.40f) {
        return 0.92f;
    }
    return 0.15f;
}

} // namespace sentinel::modules::ndr