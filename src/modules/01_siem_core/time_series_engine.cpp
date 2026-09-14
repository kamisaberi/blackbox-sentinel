#include "time_series_engine.hpp"
#include <numeric>

namespace sentinel::modules::siem {

TimeSeriesEngine::TimeSeriesEngine(size_t bucket_count)
    : bucket_count_(bucket_count), buckets_(bucket_count, 0) {
    last_bucket_time_ = std::chrono::steady_clock::now();
}

void TimeSeriesEngine::register_event() {
    std::lock_guard<std::mutex> lock(time_series_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_bucket_time_).count();

    if (elapsed >= 1) {
        size_t steps = static_cast<size_t>(elapsed);
        for (size_t i = 0; i < steps && i < bucket_count_; ++i) {
            current_bucket_idx_ = (current_bucket_idx_ + 1) % bucket_count_;
            buckets_[current_bucket_idx_] = 0;
        }
        last_bucket_time_ = now;
    }

    buckets_[current_bucket_idx_]++;
}

double TimeSeriesEngine::get_current_rate_eps() {
    std::lock_guard<std::mutex> lock(time_series_mutex_);
    uint64_t sum = std::accumulate(buckets_.begin(), buckets_.end(), 0ULL);
    return static_cast<double>(sum) / static_cast<double>(bucket_count_);
}

bool TimeSeriesEngine::detect_spike(double threshold_multiplier) {
    std::lock_guard<std::mutex> lock(time_series_mutex_);
    if (bucket_count_ <= 1) return false;

    uint64_t current = buckets_[current_bucket_idx_];
    uint64_t sum_previous = 0;
    size_t count_previous = 0;

    for (size_t i = 0; i < bucket_count_; ++i) {
        if (i != current_bucket_idx_) {
            sum_previous += buckets_[i];
            count_previous++;
        }
    }

    double baseline_avg = count_previous > 0 ? (static_cast<double>(sum_previous) / count_previous) : 1.0;
    if (baseline_avg < 1.0) baseline_avg = 1.0;

    return static_cast<double>(current) >= (baseline_avg * threshold_multiplier);
}

} // namespace sentinel::modules::siem