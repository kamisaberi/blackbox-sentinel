#pragma once
#include <string>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace sentinel::nexus_client {

struct BlockedIpEntry {
    uint32_t ipv4_net_order;
    uint64_t expires_at_ns;
    std::string rule_id;
};

class KernelDropInjector {
public:
    static KernelDropInjector& instance() {
        static KernelDropInjector inst;
        return inst;
    }

    // Initializes connection to pinned BPF map or opens BPF map by name
    bool initialize(const std::string& pinned_map_path = "/sys/fs/bpf/blocked_ip_map");

    // Injects an IPv4 address into the eBPF kernel map for sub-microsecond line-rate dropping
    bool block_ip(const std::string& ip_str, uint64_t expires_at_ns, const std::string& rule_id);

    // Removes an IPv4 address from the eBPF map (for emergency false-positive purges)
    bool unblock_ip(const std::string& ip_str);

    size_t active_in_kernel_blocks() const;

private:
    KernelDropInjector() = default;
    static uint32_t ip_string_to_net_order(const std::string& ip_str);

    mutable std::mutex mutex_;
    std::string pinned_map_path_{"/sys/fs/bpf/blocked_ip_map"};
    int bpf_map_fd_{-1};
    std::unordered_map<std::string, BlockedIpEntry> active_blocks_;
};

} // namespace sentinel::nexus_client