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
