# Subsystem 25: Financial Transaction Graph Anomaly Analyzer (`25_fdp`)

`25_fdp` inspects high-frequency financial protocol streams (e.g., **ISO 20022 XML, FIX Protocol, and SWIFT MT messages**) over internal banking networks, identifying automated account draining, front-running attacks, and transaction graph anomalies.

---

## 1. Graph Analysis Pipeline

```text
 [ Ingress Transaction Stream: ISO 20022 / FIX 4.4 ]
                        │
                        ▼ Zero-Copy XML/Tag-Value Parser
 ┌─────────────────────────────────────────────────────────────┐
 │ Entity Transaction Directed Graph                           │
 │  - Nodes: Accounts, Routing Numbers, Originating Terminals  │
 │  - Edges: Transaction Amounts, Currencies, Latency Deltas   │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ Cycle & Velocity Anomaly Traps
 ┌─────────────────────────────────────────────────────────────┐
 │ Heuristic Rules:                                            │
 │  • Rapid Multi-Hop Smurfing (< 50ms account hops)           │
 │  • Sudden High-Volume Egress Outside Operational Baselines  │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ Anomaly Confirmed
 [ Invalidate Transaction Session & Push Source IP to eBPF Map ]
```

---

## 2. Performance SLA

* **Parsing Latency:** $< 18\,\mu\text{s}$ per FIX 4.4 transaction frame.
* **Memory Safety:** Operates on pre-allocated graph nodes, discarding completed transaction branches after verification.

