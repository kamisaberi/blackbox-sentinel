#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace sentinel::modules::ztna {

struct DeviceTrustProfile {
    std::string device_id;
    uint32_t trust_score{100}; // Score from 0 (Untrusted) to 100 (Full Trust)
    uint32_t anomaly_count{0};
    std::chrono::system_clock::time_point last_updated;
};

class DynamicTrustCalculator {
public:
    DynamicTrustCalculator() = default;
    ~DynamicTrustCalculator() = default;

    uint32_t evaluate_trust(const std::string& device_id, float observed_risk);
    uint32_t get_score(const std::string& device_id);

private:
    std::unordered_map<std::string, DeviceTrustProfile> profiles_;
    std::mutex trust_mutex_;
};

} // namespace sentinel::modules::ztna