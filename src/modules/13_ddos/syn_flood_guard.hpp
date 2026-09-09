#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>
#include <chrono>

namespace sentinel::modules::ddos {

class SYNFloodGuard {
public:
    explicit SYNFloodGuard(uint32_t threshold_syn_per_sec = 2000);
    ~SYNFloodGuard() = default;

    bool evaluate_syn_packet(const std::string& src_ip, double& out_current_rate);

private:
    uint32_t threshold_syn_per_sec_;
    std::unordered_map<std::string, std::pair<uint32_t, std::chrono::steady_clock::time_point>> ip_tracker_;
    std::mutex syn_mutex_;
};

} // namespace sentinel::modules::ddos