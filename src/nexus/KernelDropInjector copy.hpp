#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <filesystem>

namespace sentinel::nexus
{

    class KernelDropInjector
    {
    public:
        static KernelDropInjector &instance();

        /// Initialize connection to pinned eBPF map (/sys/fs/bpf/blackbox_blocked_ips)
        bool initialize(const std::filesystem::path &pinned_map_path = "/sys/fs/bpf/blackbox_blocked_ips");

        /// Directly inject an IPv4 address into in-kernel blocked_ip_map for driver-level drop (< 0.84 µs)
        int inject_drop_ipv4(uint32_t ipv4, uint32_t duration_sec);

        /// Check if an IP is currently blocked in kernel map
        bool is_ip_blocked(uint32_t ipv4);

        /// Purge an IP from kernel map (emergency false-positive unblock)
        bool remove_drop_ipv4(uint32_t ipv4);

        [[nodiscard]] uint64_t total_drops_injected() const { return drops_injected_.load(); }
        [[nodiscard]] int map_fd() const { return bpf_map_fd_; }

    private:
        KernelDropInjector() = default;
        ~KernelDropInjector();

        int bpf_map_fd_{-1};
        std::atomic<uint64_t> drops_injected_{0};
    };

} // namespace sentinel::nexus