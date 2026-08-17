#pragma once
#include <string>

namespace sentinel::hardware {

struct SystemHealthMetrics {
    float cpu_usage_percent;
    float ram_usage_percent;
    float npu_gpu_load_percent;
    float cpu_temp_celsius;
    size_t memory_used_mb;
    size_t memory_total_mb;
};

class HardwareMonitor {
public:
    HardwareMonitor() = default;
    ~HardwareMonitor() = default;

    // Reads Linux /proc & /sys entries to calculate system health
    SystemHealthMetrics get_current_metrics();
};

} // namespace sentinel::hardware