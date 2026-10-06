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

