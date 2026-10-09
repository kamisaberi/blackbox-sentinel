#include "KernelDropInjector.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <chrono>
#include <iostream>
#include <arpa/inet.h>

namespace sentinel::nexus
{

    KernelDropInjector &KernelDropInjector::instance()
    {
        static KernelDropInjector inst;
        return inst;
    }

    KernelDropInjector::~KernelDropInjector()
    {
        if (bpf_map_fd_ >= 0)
        {
            close(bpf_map_fd_);
            bpf_map_fd_ = -1;
        }
    }

    bool KernelDropInjector::initialize(const std::filesystem::path &pinned_map_path)
    {
        if (bpf_map_fd_ >= 0)
            return true;

        // Attempt to open the pinned eBPF map from /sys/fs/bpf
        if (std::filesystem::exists(pinned_map_path))
        {
            bpf_map_fd_ = bpf_obj_get(pinned_map_path.c_str());
            if (bpf_map_fd_ >= 0)
            {
                std::cout << "[+] [eBPF Core] Successfully attached to live kernel map: "
                          << pinned_map_path << " (fd: " << bpf_map_fd_ << ")" << std::endl;
                return true;
            }
        }

        // In local dev/VM testing if map is not pre-pinned, create an in-process fallback BPF map
        bpf_map_fd_ = bpf_map_create(BPF_MAP_TYPE_HASH,
                                     "blocked_ip_map",
                                     sizeof(uint32_t), // key: ipv4
                                     sizeof(uint64_t), // value: expire_timestamp_ns
                                     65536,
                                     nullptr);

        if (bpf_map_fd_ >= 0)
        {
            std::cout << "[+] [eBPF Core] Created kernel BPF hash map for sub-microsecond drops (fd: "
                      << bpf_map_fd_ << ")" << std::endl;
            return true;
        }

        std::cerr << "[-] [eBPF Core] Failed to initialize BPF map. CAP_BPF / root required." << std::endl;
        return false;
    }

    int KernelDropInjector::inject_drop_ipv4(uint32_t ipv4, uint32_t duration_sec)
    {
        if (bpf_map_fd_ < 0)
        {
            if (!initialize())
                return -1;
        }

        // Value stores monotonic expiration timestamp in nanoseconds
        uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::steady_clock::now().time_since_epoch())
                              .count();
        uint64_t expires_ns = now_ns + (static_cast<uint64_t>(duration_sec) * 1000000000ULL);

        int res = bpf_map_update_elem(bpf_map_fd_, &ipv4, &expires_ns, BPF_ANY);
        if (res == 0)
        {
            drops_injected_.fetch_add(1, std::memory_order_relaxed);

            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            addr.s_addr = ipv4;
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

            std::cout << "\033[1;31m[KERNEL eBPF DROP]\033[0m Offloaded IP \033[1;33m"
                      << ip_str << "\033[0m to blocked_ip_map (TTL: " << duration_sec << "s)" << std::endl;
            return 0;
        }

        return -1;
    }

    bool KernelDropInjector::is_ip_blocked(uint32_t ipv4)
    {
        if (bpf_map_fd_ < 0)
            return false;
        uint64_t expires_ns = 0;
        return (bpf_map_lookup_elem(bpf_map_fd_, &ipv4, &expires_ns) == 0);
    }

    bool KernelDropInjector::remove_drop_ipv4(uint32_t ipv4)
    {
        if (bpf_map_fd_ < 0)
            return false;
        return (bpf_map_delete_elem(bpf_map_fd_, &ipv4) == 0);
    }

} // namespace sentinel::nexus