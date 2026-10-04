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