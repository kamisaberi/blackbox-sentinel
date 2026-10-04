---

### File: `blackbox-sentinel/docs/architecture/unidirectional-pipeline.md`

```markdown
# The Unidirectional Processing Pipeline

To maintain high throughput ($> 1{,}250{,}000\text{ EPS}$) and avoid thread synchronization deadlocks, `blackbox-sentinel` processes all network data through a **five-stage unidirectional pipeline**. Packets flow strictly forward from physical ingress to kernel mitigation.

---

## 1. Five-Stage Execution Flow

```text
 [ PHYSICAL INGRESS: 10GbE Fiber / SPAN Port / TAP ]
                        │
                        ▼ STAGE 1: INGRESS HARVESTING
 ┌─────────────────────────────────────────────────────────────┐
 │ Native AF_XDP Zero-Copy Ingestion or Raw Promiscuous Sniff  │
 │  - Zero copy into pre-allocated UMEM / Circular Ring Chunks │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ STAGE 2: PROTOCOL DISSECTION & VECTORIZATION
 ┌─────────────────────────────────────────────────────────────┐
 │ Protocol Dissector Plugins (Modbus, S7, DNP3, DICOM, etc.) │
 │  - Extracts APDU fields, registers, and timing deltas       │
 │  - Normalizes metrics into 32-dim/42-dim float feature span │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ STAGE 3: NEURAL INFERENCE EVALUATION
 ┌─────────────────────────────────────────────────────────────┐
 │ xinfer::InferenceEngine (Tier 1 Acceleration)               │
 │  - Heterogeneous Execution (OpenVINO NPU / TensorRT / CPU)  │
 │  - Calculates Reconstruction Loss (MSE) / Softmax Score     │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ STAGE 4: IN-KERNEL ACTIVE MITIGATION
 ┌─────────────────────────────────────────────────────────────┐
 │ blackbox::XdpManager::block_ip() (Tier 2 eBPF Fast Path)    │
 │  - If Score > Threshold: Inserts IPv4 into blocked_ip_map   │
 │  - Subsequent frames dropped in < 0.84 µs at driver hook    │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ STAGE 5: STRUCTURED TELEMETRY EGRESS
 ┌─────────────────────────────────────────────────────────────┐
 │ Telemetry Dispatch & SIEM Storage                           │
 │  - Local In-Memory SIEM Indexer (01_siem_core)              │
 │  - Web Command Center (Port 8443 Real-Time SVG Graphs)      │
 │  - NexusUplink (gRPC Port 50051 Fleet Collective Defense)   │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Pipelining Invariants

* **No Backwards Signaling:** A downstream subsystem never blocks an upstream ingestion worker. Telemetry logging and forensic PCAP writes operate asynchronously.
* **Deterministic Forward Hand-off:** Memory pointers are passed across pipeline stages using `std::span` and move-constructed event handles, ensuring zero heap reallocation between ingress and egress.
```

---

### File: `blackbox-sentinel/docs/architecture/memory-safety-invariants.md`

```markdown
# Memory Safety Invariants & Zero Heap Fragmentation

Edge security appliances deployed in mission-critical environments must run continuously for months or years without degradation. Traditional C/C++ daemons often succumb to heap fragmentation, memory leaks, and unbounded virtual memory expansion over time.

`blackbox-sentinel` enforces strict **memory safety invariants** across all 26 subsystems.

---

## 1. Zero Dynamic Allocation on the Fast Path

During steady-state packet evaluation, no subsystem is permitted to invoke `malloc()`, `calloc()`, `new`, or standard dynamic resizing operations (e.g., `std::vector::push_back` beyond capacity):

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Appliance Initialization Phase:                             │
 │  - Pre-allocates all 26 subsystem state matrices            │
 │  - Pins memory pools via mlock()                            │
 │  - Reserves ring buffer slots and scratchpads               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ TRANSITION TO ACTIVE STEADY-STATE
 ┌─────────────────────────────────────────────────────────────┐
 │ Operational Packet Mitigation Phase:                        │
 │  - Zero heap allocations                                    │
 │  - Fixed-size circular slot reuse                           │
 │  - RAII-scoped stack variables only                         │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Fixed-Capacity State Matrices

Subsystems that track state over time (such as User and Entity Behavior Analytics, `02_ueba`, and Network Detection, `03_ndr`) maintain fixed-capacity circular maps:

```cpp
#include <array>
#include <atomic>
#include <cstdint>

namespace sentinel {

template <typename Key, typename Value, size_t Capacity>
class FixedStateMatrix {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");

public:
    Value* acquire_or_evict(const Key& key) noexcept {
        size_t bucket = hash(key) & (Capacity - 1);
        // Eviction policy operates within statically pre-allocated memory
        entries_[bucket].key = key;
        entries_[bucket].last_seen = get_timestamp();
        return &entries_[bucket].value;
    }

private:
    struct Entry {
        Key key{};
        Value value{};
        uint64_t last_seen{0};
    };

    std::array<Entry, Capacity> entries_{};
};

} // namespace sentinel
```

---

## 3. Resident Set Size (RSS) Bounding

* **Maximum Permitted RAM Footprint:** Configured strictly via `/etc/sentinel/sentinel.yaml` (default: $2.0\text{ GB}$).
* **Memory Pool Overcommit Prevention:** If an unexpected traffic surge occurs, excess telemetry events trigger **Tail Drop** inside the SPMC ring buffer rather than dynamic memory expansion, preventing host kernel Out-of-Memory (OOM) panic events.
```

---

### File: `blackbox-sentinel/docs/architecture/dynamic-plugin-loader.md`

```markdown
# Dynamic Dissector Plugin Architecture & Symbol Isolation

The 30 industrial protocol dissector plugins (e.g., Modbus, Siemens S7Comm, DICOM, MAVLink) are compiled as modular shared libraries (`libsentinel_plugin_*.so`) and loaded dynamically at runtime via `dlopen`.

---

## 1. Symbol Encapsulation via `RTLD_LAZY | RTLD_LOCAL`

To prevent conflicting third-party symbols or cross-dissector symbol contamination, plugins are loaded with strict local visibility:

```cpp
#include <dlfcn.h>
#include <stdexcept>
#include <string>

void* load_dissector_plugin(const std::string& path) {
    ::dlerror(); // Clear error buffer

    // RTLD_LAZY : Resolve unresolved symbols as instructions execute
    // RTLD_LOCAL: Symbols defined inside this plugin are NOT visible to other plugins
    void* handle = ::dlopen(path.c_str(), RTLD_LAZY | RTLD_LOCAL);
    
    if (!handle) {
        throw std::runtime_error("Plugin load failed: " + std::string(::dlerror()));
    }
    return handle;
}
```

---

## 2. Dissector ABI Contract (`<sentinel/dissector_interface.hpp>`)

Each dissector plugin implements a pure virtual interface and exports standard factory symbols:

```cpp
#pragma once

#include <span>
#include <string_view>
#include <cstdint>

namespace sentinel {

struct DissectionResult {
    bool is_protocol_match{false};
    bool is_anomaly_detected{false};
    uint32_t rule_id{0};
    std::string_view description{};
    std::span<const float> extracted_features{};
};

class IDissectorPlugin {
public:
    virtual ~IDissectorPlugin() = default;

    [[nodiscard]] virtual std::string_view protocol_name() const noexcept = 0;
    [[nodiscard]] virtual uint16_t default_port() const noexcept = 0;

    // Zero-allocation packet dissection pass
    virtual DissectionResult dissect_packet(
        std::span<const uint8_t> payload, 
        uint64_t timestamp_ns
    ) = 0;
};

} // namespace sentinel

// Unmangled C factory export signatures
extern "C" {
    sentinel::IDissectorPlugin* create_dissector();
    void destroy_dissector(sentinel::IDissectorPlugin* plugin);
    const char* get_dissector_abi_version();
}
```

---

## 3. ABI Handshake Verification

Before activating a protocol plugin, `blackbox-sentinel` queries `get_dissector_abi_version()`. If the ABI version does not match `SENTINEL_DISSECTOR_ABI_V1`, the plugin is rejected immediately to prevent memory corruption.
```

---

### File: `blackbox-sentinel/docs/architecture/port-arbitration-model.md`

```markdown
# Port Arbitration: Promiscuous Raw Sockets vs. Secondary VIPs

Deploying an active security daemon on an industrial network creates an operational challenge: how does the appliance monitor, inspect, and defend critical ports (such as Modbus on port `502` or S7Comm on port `102`) without conflicting with legitimate PLC control software running on the same host?

`blackbox-sentinel` resolves this using **Dual-Mode Port Arbitration**.

---

## 1. The Conflict Dilemma

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ CONFLICT SCENARIO:                                          │
 │ Legitimate Local SCADA Server binds to 0.0.0.0:502          │
 │ Deception Decoy / Honey-PLC attempts to bind to 0.0.0.0:502 │
 │ RESULT: Bind failure -> Address already in use (EADDRINUSE) │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. The Solution: Dual-Mode Port Arbitration

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                       PHYSICAL INTERFACE: eth0                              │
 │            Primary IP: 10.240.0.100 (Host & Legitimate Services)            │
 └──────────────────────┬──────────────────────────────┬───────────────────────┘
                        │                              │
         MODE 1: PASSIVE SNIFFING                      │ MODE 2: DECEPTION VIPs
         Promiscuous AF_XDP / Raw Sockets              │ Secondary Virtual IP:
         (Zero Socket Binding)                         │ eth0:1 = 10.240.0.199
                        │                              │
                        ▼                              ▼
         ┌─────────────────────────────┐        ┌─────────────────────────────┐
         │ Passive Inspection Engine   │        │ 26_ddp (Decoy Honey-PLC)    │
         │ - Sniffs traffic invisibly  │        │ - Explicitly binds to       │
         │ - Zero port collisions      │        │   10.240.0.199:502 via      │
         │ - Subsystems 01-25 Active   │        │   SO_BINDTODEVICE           │
         └─────────────────────────────┘        └─────────────────────────────┘
```

---

## 3. Secondary VIP Binding Logic

When the deception subsystem (`26_ddp`) launches decoy Modbus or Siemens PLCs:
1. It registers an isolated virtual IP alias (e.g., `ip addr add 10.240.0.199/24 dev eth0 label eth0:1`).
2. Decoy listeners bind exclusively to the virtual IP (`10.240.0.199`) using `SO_BINDTODEVICE`, leaving `10.240.0.100` and `0.0.0.0` unencumbered.
3. Legitimate plant PLCs continue normal operations while adversaries scanning the subnet interact with the isolated honeypot environment.
```

---

### File: `blackbox-sentinel/docs/architecture/under-the-hood-bindings.md`

```markdown
# In-Process Bindings to Tier 1 (`libxinfer`) & Tier 2 (`libblackbox`)

`blackbox-sentinel` operates as an integrated Tier 3 appliance daemon by binding directly in-process to **`libxinfer.so`** and **`libblackbox.so`**, avoiding IPC serialization and process-switching overhead.

---

## 1. Unified Shared-Memory Architecture

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                  sentinel Appliance Process (Address Space)                 │
 │                                                                             │
 │  ┌───────────────────────────────────────────────────────────────────────┐  │
 │  │ blackbox-sentinel Orchestrator & Subsystems                           │  │
 │  └───────────────────┬───────────────────────────────▲───────────────────┘  │
 │                      │ In-Process API Calls          │                      │
 │                      ▼                               │ Telemetry Stream     │
 │  ┌───────────────────────────────────┐ ┌─────────────┴───────────────────┐  │
 │  │ Tier 1: libxinfer.so              │ │ Tier 2: libblackbox.so          │  │
 │  │ - xinfer::InferenceEngine         │ │ - blackbox::XdpManager          │  │
 │  │ - Zero-Copy Tensor Input Views    │ │ - blackbox::EventRingBuffer     │  │
 │  │ - Hardware Accelerator Contexts   │ │ - In-Kernel eBPF Map Direct FDs │  │
 │  └───────────────────────────────────┘ └─────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. In-Process Packet Flow Implementation

```cpp
#include <blackbox/blackbox.hpp>
#include <xinfer/xinfer.hpp>
#include <sentinel/orchestrator.hpp>

namespace sentinel {

class PipelineBridge {
public:
    PipelineBridge(blackbox::XdpManager& xdp, xinfer::InferenceEngine& ai)
        : xdp_(xdp), ai_(ai) {}

    // Executed by worker threads dequeuing from EventRingBuffer
    void process_flow_event(const blackbox::FlowEvent& evt) {
        // Step 1: Map event features directly into Tier 1 tensor (Zero-Copy)
        auto input_tensor = ai_.get_input_tensor(0);
        float* tensor_mem = input_tensor->data<float>();
        
        // Fast-path feature extraction into pinned tensor buffer
        tensor_mem[0] = static_cast<float>(evt.packet_length) / 1500.0f;
        tensor_mem[1] = static_cast<float>(evt.protocol) / 255.0f;

        // Step 2: Execute AI forward pass (< 12 µs on Intel NPU / TensorRT)
        ai_.forward();

        // Step 3: Evaluate Threat Anomaly Score
        float anomaly_score = *ai_.get_output_tensor(0)->data<float>();

        // Step 4: Trigger In-Kernel Mitigation via Tier 2 Driver Hook
        if (anomaly_score > 0.85f) {
            // Drops subsequent packets from this IP in < 0.84 µs
            xdp_.block_ip(evt.src_ip, /*ttl_seconds=*/60, /*rule_id=*/1801);
        }
    }

private:
    blackbox::XdpManager& xdp_;
    xinfer::InferenceEngine& ai_;
};

} // namespace sentinel
```

---

## 3. Linker Configuration

`sentinel` links directly against the foundational tier libraries in its build configuration:

```cmake
target_link_libraries(sentinel
    PRIVATE
        xinfer::xinfer
        blackbox::blackbox
        pthread
        dl
)
```
```

---

### Complete in Part 2
- `blackbox-sentinel/docs/architecture/appliance-architecture.md`
- `blackbox-sentinel/docs/architecture/unidirectional-pipeline.md`
- `blackbox-sentinel/docs/architecture/memory-safety-invariants.md`
- `blackbox-sentinel/docs/architecture/dynamic-plugin-loader.md`
- `blackbox-sentinel/docs/architecture/port-arbitration-model.md`
- `blackbox-sentinel/docs/architecture/under-the-hood-bindings.md`

All 6 core architecture files for `blackbox-sentinel` are now generated.

---

### Files to be Generated in Part 3

The next phase begins covering the **26 Native C++ Subsystems** (`subsystems-26/`). Part 3 will deliver the complete index along with the **Enterprise IT & Detection** and **Web Application Protection** modules:

1. `subsystems-26/index.md` (Subsystem overview & runtime dependency matrix)
2. `subsystems-26/enterprise-it/01-siem-core.md` (`01_siem_core`: In-memory log correlation & indexer)
3. `subsystems-26/enterprise-it/02-ueba.md` (`02_ueba`: User & Entity Behavior Analytics, 100k state matrix)
4. `subsystems-26/enterprise-it/03-ndr.md` (`03_ndr`: Network Detection & Response, TLS JA3/JA4 analysis)
5. `subsystems-26/enterprise-it/04-ids-ips.md` (`04_ids_ips`: Inline signature matching & eBPF driver drops)
6. `subsystems-26/enterprise-it/15-ngfw.md` (`15_ngfw`: Next-Gen Firewall Deep Packet Inspection)
7. `subsystems-26/web-application/05-waf.md` (`05_waf`: Web Application & API Protection, SQLi, XSS, BOLA)
8. `subsystems-26/web-application/10-bad.md` (`10_bad`: Bot & Automated Abuse Defense, Kinematic curves)
9. `subsystems-26/web-application/11-rasp.md` (`11_rasp`: Runtime Application Self-Protection, In-memory hook guard)

Confirm when you are ready to proceed with Part 3.