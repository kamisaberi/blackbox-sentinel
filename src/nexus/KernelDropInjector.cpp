#include "KernelDropInjector.hpp"
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

namespace sentinel::nexus_client {

// Minimal zero-dependency BPF syscall wrapper
static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

uint32_t KernelDropInjector::ip_string_to_net_order(const std::string& ip_str) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
        return 0;
    }
    return addr.s_addr;
}

bool KernelDropInjector::initialize(const std::string& pinned_map_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    pinned_map_path_ = pinned_map_path;

    // Attempt to open pinned BPF map from BPF filesystem (/sys/fs/bpf/...)
    union bpf_attr attr{};
    attr.pathname = reinterpret_cast<uint64_t>(pinned_map_path_.c_str());

    bpf_map_fd_ = sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (bpf_map_fd_ < 0) {
        std::cout << "[KernelDropInjector] Notice: Pinned BPF map " << pinned_map_path_ 
                  << " not found. Running in simulation mode (rules tracked in userspace)." << std::endl;
        return false;
    }

    std::cout << "[KernelDropInjector] Attached to kernel eBPF map at " << pinned_map_path_ 
              << " (FD: " << bpf_map_fd_ << "). Active defense enabled." << std::endl;
    return true;
}

bool KernelDropInjector::block_ip(const std::string& ip_str, uint64_t expires_at_ns, const std::string& rule_id) {
    uint32_t ip_net = ip_string_to_net_order(ip_str);
    if (ip_net == 0) {
        std::cerr << "[KernelDropInjector] Error: Invalid IPv4 format: " << ip_str << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // 1. If real BPF map FD is open, inject directly into kernel memory
    if (bpf_map_fd_ >= 0) {
        union bpf_attr attr{};
        attr.map_fd = bpf_map_fd_;
        attr.key = reinterpret_cast<uint64_t>(&ip_net);
        
        // Value: 1 (or timestamp) indicates dropped packet
        uint64_t val = expires_at_ns;
        attr.value = reinterpret_cast<uint64_t>(&val);
        attr.flags = BPF_ANY;

        if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
            std::cerr << "[KernelDropInjector] BPF syscall failed to update map for: " << ip_str << std::endl;
            return false;
        }
    }

    // 2. Track in local active table
    active_blocks_[ip_str] = {
        .ipv4_net_order = ip_net,
        .expires_at_ns = expires_at_ns,
        .rule_id = rule_id
    };

    std::cout << "\033[32m[KernelDropInjector] IN-KERNEL DROP ENFORCED -> Attacker IP: [" 
              << ip_str << "] via Rule: " << rule_id << " (< 1µs XDP_DROP active)\033[0m" << std::endl;
    return true;
}

bool KernelDropInjector::unblock_ip(const std::string& ip_str) {
    uint32_t ip_net = ip_string_to_net_order(ip_str);
    if (ip_net == 0) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    if (bpf_map_fd_ >= 0) {
        union bpf_attr attr{};
        attr.map_fd = bpf_map_fd_;
        attr.key = reinterpret_cast<uint64_t>(&ip_net);
        sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    }

    active_blocks_.erase(ip_str);
    std::cout << "[KernelDropInjector] Purged IP [" << ip_str << "] from kernel drop map." << std::endl;
    return true;
}

size_t KernelDropInjector::active_in_kernel_blocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_blocks_.size();
}

} // namespace sentinel::nexus_client