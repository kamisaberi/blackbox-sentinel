# Real-Time Telemetry Streaming & Dashboard Architecture

The Web Command Center renders real-time telemetry updates using **Server-Sent Events (SSE)** over `/api/v1/telemetry/stream`, streaming metrics directly from the in-memory ring buffers to the browser without polling overhead.

---

## 1. High-Frequency Telemetry Dashboard

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     BLACKBOX SENTINEL COMMAND CENTER                        │
 │ Node: edge-substation-alpha | Stage: STAGE_FULL_ACTIVE | TPM: TIER 1 (IFX) │
 ├───────────────────────────────────┬─────────────────────────────────────────┤
 │ HARDWARE REAL-TIME HEALTH         │ IN-KERNEL ACTIVE MITIGATION             │
 │ • CPU Ingress Core 0: 4.2%        │ • Drop SLA Guaranteed : < 0.84 µs       │
 │ • Worker Pool (Cores 1-7): 2.1%   │ • Last Drop Reaction  : 0.81 µs         │
 │ • Host RAM Footprint : 1.4 GB     │ • Active Blocked IPs  : 4 Active Rules  │
 │ • NPU Silicon Temp   : 44.2°C     │ • Total Drops Today   : 142,891 Packets │
 ├───────────────────────────────────┴─────────────────────────────────────────┤
 │ THROUGHPUT DYNAMICS (HTML5 Canvas 10-Second Sliding Window)                 │
 │  1.25M EPS ──┐                                                              │
 │              │      /\    /\                                                │
 │   500k EPS ──┼─────/  \--/  \-----------------------------------------------│
 │     0k EPS ──┴──────────────────────────────────────────────────────────────│
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Server-Sent Events (SSE) Dispatcher (`WebTelemetryStream.cpp`)

```cpp
#include <string>
#include <sstream>
#include <blackbox/telemetry.hpp>

namespace sentinel::web {

std::string serialize_sse_telemetry(
    const blackbox::KernelTelemetry& kernel, 
    double cpu_usage, 
    double npu_temp
) {
    std::ostringstream ss;
    ss << "event: telemetry_tick\n"
       << "data: {"
       << "\"timestamp_ns\":" << get_monotonic_ns() << ","
       << "\"cpu_ingress_percent\":" << cpu_usage << ","
       << "\"npu_temperature_c\":" << npu_temp << ","
       << "\"packets_processed\":" << kernel.total_packets_processed << ","
       << "\"packets_dropped\":" << kernel.total_packets_dropped << ","
       << "\"active_rules\":" << kernel.active_blocked_ips << ","
       << "\"drop_rate_pct\":" << kernel.drop_rate_percentage
       << "}\n\n";

    return ss.str();
}

} // namespace sentinel::web
```

---

## 3. Client-Side Rendering Invariants

* **HTML5 Canvas:** Throughput sparklines and latency histograms are drawn directly onto an HTML5 Canvas element via vanilla JavaScript requestAnimationFrame loops, bypassing heavy charting libraries.
* **Low Client CPU Footprint:** The entire dashboard UI consumes $< 1\%$ CPU on an administrative laptop.

