#pragma once

#include <blackbox/event.hpp>
#include <vector>
#include <cstdint>

namespace sentinel::modules::ndr {

struct FlowStatistics {
    uint32_t packet_count{0};
    double byte_count{0.0};
    double duration_ms{0.0};
    float mean_packet_size{0.0f};
    float syn_ratio{0.0f};
};

class FlowAnalyzer {
public:
    FlowAnalyzer() = default;
    ~FlowAnalyzer() = default;

    FlowStatistics extract_flow_stats(const blackbox::SecurityEvent& event);
    std::vector<float> build_flow_tensor(const FlowStatistics& stats);
};

} // namespace sentinel::modules::ndr