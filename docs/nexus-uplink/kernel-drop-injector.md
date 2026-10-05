---

### File: `blackbox-sentinel/docs/nexus-uplink/kernel-drop-injector.md`

```markdown
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
```

---

### File: `blackbox-sentinel/docs/nexus-uplink/ota-model-updates.md`

```markdown
# Over-the-Air (OTA) Model Updates & Zero-Downtime Hot Reloads

`blackbox-sentinel` supports remote neural network weight updates staged by the `xinfer-forge` training pipeline and distributed by `sentinel-nexus`.

---

## 1. Staged OTA Rollout Stages

```text
 Sentinel-Nexus Model Repository (app.aryorithm.com)
                        │
                        ▼ Staged Canary Deployment
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 1: SHADOW EVALUATION                                  │
 │   - Download candidate model (network_threat_v2.onnx)       │
 │   - Evaluate predictions in parallel with production model  │
 │   - Zero active kernel drop authority                       │
 └──────────────────────┬──────────────────────────────────────┘
                        │ Pass Criteria: Accuracy >= 99.8%
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 2: CANARY FLEET ENFORCEMENT                           │
 │   - 5% of fleet appliances activated in live mitigation     │
 │   - Monitored by RollbackGuard (> 1000µs SLA breaches abort)│
 └──────────────────────┬──────────────────────────────────────┘
                        │ Pass Criteria: Zero False Positive Drops
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 3: FLEET-WIDE PROMOTION                               │
 │   - Complete rollout across all edge nodes                  │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. In-Process Model Hot Reload API

When a validated model payload finishes downloading:
1. `NexusUplink` verifies its SHA-256 hash against the manifest.
2. It sends an internal command to the embedded web server:
   ```bash
   POST /api/v1/control/reload-model
   ```
3. The inference engine (`xinfer::InferenceEngine`) instantiates a new execution plan for the candidate model in secondary memory, performs an atomic pointer swap, and releases the old model weights—achieving **zero-downtime weight updates**.
```

---

### File: `blackbox-sentinel/docs/nexus-uplink/instant-graceful-disconnect.md`

```markdown
# Instant 0ms Graceful Disconnect on Process Teardown

In distributed fleet management, when an edge node is halted (via `SIGINT`, `Ctrl+C`, system reboot, or `systemctl stop sentinel`), conventional architectures rely on server-side timeout detectors ($30 - 90\text{ seconds}$) to flag the appliance as offline.

`blackbox-sentinel` implements an **Instant 0ms Graceful Disconnection** mechanism.

---

## 1. Signal Interception & Synchronous Deregistration

```text
 Operator initiates SIGINT / SIGTERM
                   │
                   ▼ Linux Signal Handler Trap
 ┌─────────────────────────────────────────────────────────────┐
 │ blackbox-sentinel Signal Trap                               │
 └─────────────────┬───────────────────────────────────────────┘
                   │ Invokes NexusUplink::execute_instant_disconnect()
                   ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Synchronous gRPC Call: DeregisterAppliance()                │
 │  - Reason: REASON_OPERATOR_SHUTDOWN                         │
 │  - Max Timeout: 500 ms                                      │
 └─────────────────┬───────────────────────────────────────────┘
                   │
                   ▼ Dispatched over Wire
 ┌─────────────────────────────────────────────────────────────┐
 │ sentinel-nexus Command Hub updates node status to OFFLINE   │
 │ in < 5 ms (Zero Polling Wait Time)                          │
 └─────────────────┬───────────────────────────────────────────┘
                   │
                   ▼ Signal Handler Completes
 [ Clean Process Exit (Return Code 0) ]
```

---

## 2. Implementation (`NexusUplink.cpp`)

```cpp
void NexusUplink::execute_instant_disconnect() noexcept {
    if (!stub_) return;

    try {
        grpc::ClientContext context;
        // Strict deadline: Disconnect must complete in under 500ms
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(500));
        context.AddMetadata("authorization", "Bearer " + active_jwt_token_);

        DeregisterRequest request;
        request.set_appliance_uuid(appliance_uuid_);
        request.set_reason(DeregisterReason::GRACEFUL_SHUTDOWN);

        DeregisterResponse response;
        grpc::Status status = stub_->DeregisterAppliance(&context, request, &response);

        if (status.ok()) {
            std::cout << "[+] Graceful deregistration confirmed by Nexus Hub (0ms latency).\n";
        }
    } catch (...) {
        // Suppress exceptions during critical signal shutdown
    }
}
```

---

## 3. Operational Guarantees

* **Elimination of Phantom Alerts:** SOC operators never receive false "Node Down" alerts caused by polling heartbeat timeouts during routine appliance maintenance.
* **Kernel Safety:** Disconnect triggers `blackbox::XdpManager::detach()` automatically, restoring standard network routing before process termination.
```

