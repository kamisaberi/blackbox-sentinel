#include "udp_rate_limiter.hpp"
#include <algorithm>

namespace sentinel::modules::ddos {

UDPRateLimiter::UDPRateLimiter(size_t bucket_capacity, double refill_rate)
    : capacity_(bucket_capacity), refill_rate_(refill_rate) {}

bool UDPRateLimiter::check_packet(const std::string& src_ip, size_t packet_size) {
    std::lock_guard<std::mutex> lock(limiter_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& b = buckets_[src_ip];

    if (b.last_refill.time_since_epoch().count() == 0) {
        b.tokens = capacity_;
        b.last_refill = now;
    } else {
        auto elapsed = std::chrono::duration<double>(now - b.last_refill).count();
        b.tokens = std::min(static_cast<double>(capacity_), b.tokens + elapsed * refill_rate_);
        b.last_refill = now;
    }

    if (b.tokens >= static_cast<double>(packet_size)) {
        b.tokens -= packet_size;
        return true; // Allowed
    }

    return false; // Rate limit exceeded
}

} // namespace sentinel::modules::ddos