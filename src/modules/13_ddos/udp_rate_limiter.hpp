#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>
#include <chrono>

namespace sentinel::modules::ddos {

class UDPRateLimiter {
public:
    explicit UDPRateLimiter(size_t bucket_capacity = 50000, double refill_rate = 10000.0);
    ~UDPRateLimiter() = default;

    bool check_packet(const std::string& src_ip, size_t packet_size);

private:
    size_t capacity_;
    double refill_rate_;
    struct Bucket {
        double tokens;
        std::chrono::steady_clock::time_point last_refill;
    };
    std::unordered_map<std::string, Bucket> buckets_;
    std::mutex limiter_mutex_;
};

} // namespace sentinel::modules::ddos