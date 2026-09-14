#pragma once

#include <cstdint>
#include <vector>
#include <mutex>
#include <chrono>

namespace sentinel::modules::siem {

class TimeSeriesEngine {
public:
    explicit TimeSeriesEngine(size_t bucket_count = 60);
    ~TimeSeriesEngine() = default;

    void register_event();
    double get_current_rate_eps();
    bool detect_spike(double threshold_multiplier = 2.5);

private:
    size_t bucket_count_;
    std::vector<uint32_t> buckets_;
    size_t current_bucket_idx_{0};
    std::chrono::steady_clock::time_point last_bucket_time_;
    std::mutex time_series_mutex_;
};

} // namespace sentinel::modules::siem