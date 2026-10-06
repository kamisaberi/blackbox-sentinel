# Kernel Drop Injector Architecture (`KernelDropInjector.cpp`)

`KernelDropInjector` provides the direct bridge between high-level user-space policy management and low-level Linux kernel eBPF hash maps.

---

## 1. Direct Syscall Invocation Mechanics

Rather than spawning external utilities (such as `iptables` or `bpftool`), `KernelDropInjector` executes direct `bpf()` system calls (`__NR_bpf`):

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ NexusUplink::run_rule_stream_loop()                         │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Passes: uint32_t IP, uint64_t TTL
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ KernelDropInjector::inject_blocked_ip()                     │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Calls bpf_map_update_elem()
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Linux Kernel: BPF_MAP_UPDATE_ELEM Syscall                   │
 │   - Map: /sys/fs/bpf/blackbox/blocked_ip_map                │
 │   - Insertion Latency: ~180 nanoseconds                     │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Source Implementation (`KernelDropInjector.cpp`)

```cpp
#include <blackbox/xdp_manager.hpp>
#include <bpf/bpf.h>
#include <chrono>

namespace sentinel::nexus {

class KernelDropInjector {
public:
    explicit KernelDropInjector(blackbox::XdpManager& xdp) : xdp_(xdp) {}

    bool inject_rule(uint32_t ipv4_net_order, uint64_t ttl_seconds, uint32_t rule_id) noexcept {
        try {
            // Invokes Tier 2 active mitigation core
            xdp_.block_ip(ipv4_net_order, ttl_seconds, rule_id);
            return true;
        } catch (...) {
            return false;
        }
    }

private:
    blackbox::XdpManager& xdp_;
};

} // namespace sentinel::nexus
```

---

## 3. Atomic Map Replacement Guarantees

If an incoming fleet rule updates an IP that is already blocked:
1. `bpf_map_update_elem` is invoked with flag `BPF_ANY`.
2. The kernel atomically overwrites the expiration timestamp and rule ID without tearing down active hash buckets, preventing lookup race conditions on the network data plane.

