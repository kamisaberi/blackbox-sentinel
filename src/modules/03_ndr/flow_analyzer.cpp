#include "flow_analyzer.hpp"

namespace sentinel::modules::ndr {

FlowStatistics FlowAnalyzer::extract_flow_stats(const blackbox::SecurityEvent& event) {
    FlowStatistics s;
    if (!event.features.empty()) {
        s.packet_count = static_cast<uint32_t>(event.features[0] * 100.0f);
        s.byte_count = static_cast<double>(event.features[1] * 150000.0f);
        s.duration_ms = static_cast<double>(event.features[2] * 1000.0f);
        s.mean_packet_size = event.features[3] * 1500.0f;
        s.syn_ratio = event.features.size() > 4 ? event.features[4] : 0.0f;
    } else {
        s.packet_count = 1;
        s.byte_count = 64.0;
        s.duration_ms = 0.1;
        s.mean_packet_size = 64.0f;
        s.syn_ratio = 1.0f;
    }
    return s;
}

std::vector<float> FlowAnalyzer::build_flow_tensor(const FlowStatistics& stats) {
    std::vector<float> tensor(32, 0.0f);
    tensor[0] = static_cast<float>(stats.packet_count) / 1000.0f;
    tensor[1] = static_cast<float>(stats.byte_count) / 1000000.0f;
    tensor[2] = static_cast<float>(stats.duration_ms) / 5000.0f;
    tensor[3] = stats.mean_packet_size / 1500.0f;
    tensor[4] = stats.syn_ratio;
    return tensor;
}

} // namespace sentinel::modules::ndr