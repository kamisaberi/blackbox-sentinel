#pragma once

#include <string>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <atomic>

namespace sentinel::nexus_client
{
    struct BlockedIpEntry
    {
        uint32_t ipv4_net_order;
        uint64_t expires_at_ns;
        std::string rule_id;
    };

    class KernelDropInjector
    {
    public:
        static KernelDropInjector &instance()
        {
            static KernelDropInjector inst;
            return inst;
        }

        // --- ORIGINAL METHODS (PRESERVED FOR NEXUSUPLINK & ORCHESTRATOR) ---
        bool initialize(const std::string &pinned_map_path = "/sys/fs/bpf/blocked_ip_map");
        bool block_ip(const std::string &ip_str, uint64_t expires_at_ns, const std::string &rule_id);
        bool unblock_ip(const std::string &ip_str);
        size_t active_in_kernel_blocks() const;

        // --- NEW OVERLOADS (FOR EXTENSIBILITY SDK & eBPF HOOKS) ---
        int  inject_drop_ipv4(uint32_t ipv4_net_order, uint32_t duration_sec, const std::string &rule_id = "SDK_DROP");
        bool is_ip_blocked(uint32_t ipv4_net_order) const;
        bool remove_drop_ipv4(uint32_t ipv4_net_order);
        uint64_t total_drops_injected() const { return drops_injected_count_.load(); }
        int  map_fd() const { return bpf_map_fd_; }

    private:
        KernelDropInjector() = default;
        ~KernelDropInjector();
        static uint32_t ip_string_to_net_order(const std::string &ip_str);

        mutable std::mutex mutex_;
        std::string pinned_map_path_{"/sys/fs/bpf/blocked_ip_map"};
        int bpf_map_fd_{-1};
        std::unordered_map<std::string, BlockedIpEntry> active_blocks_;
        std::atomic<uint64_t> drops_injected_count_{0};
    };

} // namespace sentinel::nexus_client

// Namespace alias so any code using sentinel::nexus::KernelDropInjector also compiles
namespace sentinel::nexus {
    using KernelDropInjector = sentinel::nexus_client::KernelDropInjector;
}