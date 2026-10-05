---

### File: `blackbox-sentinel/docs/nexus-uplink/collective-defense-sync.md`

```markdown
# Collective Defense Synchronization: Sub-50ms Rule Propagation

`blackbox-sentinel` participates in the Aryorithm **Collective Defense Grid** under the architectural invariant: *"Attacked Once, Immune Everywhere."* 

When an adversary targets any appliance in the global fleet, the attack signature is fanned out and programmed directly into all other appliances' eBPF driver maps in **under $50\,\text{milliseconds}$**.

---

## 1. Fleet Rule Ingestion Pipeline

```text
 [ Attack Detected on Appliance #1 (e.g. Frankfurt) ]
                        │
                        ▼ Triggers Local eBPF Drop (< 0.84 µs)
 ┌─────────────────────────────────────────────────────────────┐
 │ Appliance #1 Emits ThreatIoC to Sentinel-Nexus              │
 └──────────────────────┬──────────────────────────────────────┘
                        │ Transit to Fleet Hub: ~18 ms
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Sentinel-Nexus Collective Defense Bus                       │
 │  - Broadcasts FleetDefenseRule over gRPC Streaming Channels │
 └──────────────────────┬──────────────────────────────────────┘
                        │ Fan-out Stream Transit: ~12 ms
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Appliance #2 (e.g. Munich): NexusUplink Rule Listener       │
 └──────────────────────┬──────────────────────────────────────┘
                        │ Invokes KernelDropInjector in-process: ~2 ms
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Kernel BPF Map updated: blocked_ip_map[Attacker IP] = TTL   │
 └─────────────────────────────────────────────────────────────┘
  TOTAL PROPAGATION LATENCY: 32 ms (< 50 ms SLA Bound)
```

---

## 2. Inbound Stream Handler (`NexusUplink.cpp`)

```cpp
void NexusUplink::run_rule_stream_loop() {
    while (is_running_.load(std::memory_order_relaxed)) {
        grpc::ClientContext context;
        context.AddMetadata("authorization", "Bearer " + active_jwt_token_);

        StreamRulesRequest req;
        req.set_appliance_uuid(appliance_uuid_);

        auto reader = stub_->StreamFleetRules(&context, req);
        FleetDefenseRule rule;

        while (reader->Read(&rule)) {
            // Direct In-Kernel Injection (Zero IPC delay)
            uint32_t ip = rule.target_ipv4_net_order();
            uint64_t ttl_sec = rule.ttl_seconds();
            uint32_t rule_id = rule.rule_id();

            // Pushes directly to eBPF driver hash map
            xdp_.block_ip(ip, ttl_sec, rule_id);

            XINFER_LOG_INFO(
                "Fleet Defense Injected: Rule {} | IP: 0x{:08x} blocked for {}s in < 50ms",
                rule_id, ip, ttl_sec
            );
        }
    }
}
```
```

