#include "syn_flood_guard.hpp"

namespace sentinel::modules::ddos {

SYNFloodGuard::SYNFloodGuard(uint32_t threshold_syn_per_sec)
    : threshold_syn_per_sec_(threshold_syn_per_sec) {}

bool SYNFloodGuard::evaluate_syn_packet(const std::string& src_ip, double& out_current_rate) {
    std::lock_guard<std::mutex> lock(syn_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& entry = ip_tracker_[src_ip];

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.second).count();
    if (elapsed >= 1000) {
        out_current_rate = static_cast<double>(entry.first);
        entry.first = 1;
        entry.second = now;
        return (out_current_rate > threshold_syn_per_sec_);
    }

    entry.first++;
    out_current_rate = (static_cast<double>(entry.first) / (elapsed + 1)) * 1000.0;
    return (entry.first > threshold_syn_per_sec_);
}

} // namespace sentinel::modules::ddos