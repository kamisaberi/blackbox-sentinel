### Part 10: Nexus Uplink Subsystem (`nexus-uplink/*`)

This section contains 7 technical implementation guides detailing the client-side fleet synchronization engine in `blackbox-sentinel`: background gRPC agent architecture, TPM-rooted registration handshakes, real-time telemetry streaming, $< 50\,\text{ms}$ collective defense rule ingestion, direct kernel BPF drop injection, OTA model hot-reloads, and 0ms instant graceful disconnects.

---

### File: `blackbox-sentinel/docs/nexus-uplink/uplink-architecture.md`

```markdown
# Nexus Uplink Architecture & Thread Model

`NexusUplink` (`src/nexus/NexusUplink.cpp`) is the client-side background subsystem responsible for maintaining continuous, bidirectional communication between an edge appliance (`blackbox-sentinel`) and the central fleet orchestrator (`sentinel-nexus`) over mutual TLS (mTLS) gRPC on port **50051**.

---

## 1. Architectural Interaction Pipeline

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ sentinel-nexus Central Command (Tier 6 Hub - Port 50051)    │
 └──────────────────────────────▲──────────────────────────────┘
                                │ Bi-Directional mTLS 1.3 Stream
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ blackbox-sentinel: NexusUplink Background Client Thread     │
 ├─────────────────────────────────────────────────────────────┤
 │ 1. Registration Handler: TPM 2.0 PCR Quotes (/dev/tpmrm0)   │
 │ 2. Heartbeat Streamer : Ingests CPU, NPU Temp, Ring Drops   │
 │ 3. Collective Defense : Ingests FleetDefenseRule (< 50ms)   │
 │ 4. OTA Model Sync     : Polls Canary Weights & Triggers Hot │
 │                         Reload (POST /reload-model)         │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Direct BPF In-Process Call
 ┌─────────────────────────────────────────────────────────────┐
 │ KernelDropInjector: Writes directly to blocked_ip_map        │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Invariants & Isolation Rules

1. **Non-Blocking Fault Isolation:** If the central `sentinel-nexus` hub becomes unreachable or network routes fail, `NexusUplink` enters an exponential backoff retry loop. In-kernel packet mitigation ($< 0.84\,\mu\text{s}$) and local SIEM indexing continue uninterrupted.
2. **Dedicated Background Thread:** Uplink communication runs on an isolated POSIX thread outside the high-frequency packet ingestion and AI inference pipelines.
3. **mTLS Cryptographic Enforcement:** Every gRPC channel requires mutual TLS verification using client certificates issued during initial hardware enrollment.

---

## 3. C++20 Thread Implementation (`NexusUplink.hpp`)

```cpp
#pragma once

#include <grpcpp/grpcpp.h>
#include <sentinel_nexus.grpc.pb.h>
#include <blackbox/xdp_manager.hpp>
#include <thread>
#include <atomic>
#include <memory>

namespace sentinel::nexus {

class NexusUplink {
public:
    NexusUplink(
        const std::string& hub_address, 
        blackbox::XdpManager& xdp, 
        const std::string& cert_dir
    );
    ~NexusUplink();

    void start();
    void stop() noexcept;

    // Instant graceful disconnection called by signal handler (SIGINT/SIGTERM)
    void execute_instant_disconnect() noexcept;

private:
    std::string hub_address_;
    blackbox::XdpManager& xdp_;
    std::string cert_dir_;
    
    std::atomic<bool> is_running_{false};
    std::jthread worker_thread_;
    std::jthread rule_stream_thread_;

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<sentinel::nexus::FleetOrchestrator::Stub> stub_;

    void run_heartbeat_loop();
    void run_rule_stream_loop();
};

} // namespace sentinel::nexus
```
```

