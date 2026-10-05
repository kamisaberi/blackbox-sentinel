---

### File: `blackbox-sentinel/docs/nexus-uplink/telemetry-and-heartbeats.md`

```markdown
# Live Telemetry Ingestion & Heartbeat Synchronization

`NexusUplink` transmits structured telemetry records every **$5.0\text{ seconds}$** via the `SubmitHeartbeat` gRPC endpoint, providing `sentinel-nexus` with visibility into host resource usage, drop counters, and active protocol sensor states.

---

## 1. 4-Tier Asset Hierarchy Alignment

Telemetry reports map directly into the Aryorithm 4-tier asset hierarchy:

$$\text{Tenant} \longrightarrow \text{Nexus Hub} \longrightarrow \text{Sentinel Appliance} \longrightarrow \text{Connected Sensors / PLCs}$$

```json
{
  "tenant_id": "tenant-municipal-water",
  "nexus_id": "nexus-central-01",
  "node_id": "edge-substation-alpha",
  "sensors": [
    { "sensor_id": "plc-schneider-m340", "protocol": "MODBUS_TCP", "ip": "10.240.0.101", "status": "ONLINE" },
    { "sensor_id": "siemens-s7-1200", "protocol": "S7COMM", "ip": "10.240.0.102", "status": "ONLINE" }
  ]
}
```

---

## 2. Heartbeat Payload Definition

```protobuf
message ApplianceHeartbeat {
    string appliance_uuid = 1;
    int64 timestamp_ns = 2;

    // Hardware Metrics
    double cpu_usage_percent = 3;
    double memory_used_bytes = 4;
    double memory_total_bytes = 5;
    double npu_temperature_celsius = 6;

    // Kernel Mitigation Metrics
    uint64 total_packets_processed = 7;
    uint64 total_packets_dropped = 8;
    uint64 active_blocked_ips = 9;
    double current_drop_latency_us = 10;

    // Attached Sensor Inventory
    repeated SensorDescriptor active_sensors = 11;
}

message SensorDescriptor {
    string sensor_id = 1;
    string protocol = 2;
    string ip_address = 3;
    uint32 port = 4;
    bool is_anomalous = 5;
}
```

---

## 3. High-Frequency Harvest Loop

The harvest loop collects metrics without locking:

```cpp
void NexusUplink::run_heartbeat_loop() {
    while (is_running_.load(std::memory_order_relaxed)) {
        ApplianceHeartbeat hb;
        hb.set_appliance_uuid(appliance_uuid_);
        hb.set_timestamp_ns(get_monotonic_ns());

        // Extract metrics from Tier 2 libblackbox
        auto telemetry = xdp_.get_telemetry();
        hb.set_total_packets_processed(telemetry.total_packets_processed);
        hb.set_total_packets_dropped(telemetry.total_packets_dropped);
        hb.set_active_blocked_ips(telemetry.active_blocked_ips);
        hb.set_current_drop_latency_us(telemetry.drop_rate_percentage);

        // Submit via gRPC client stub
        grpc::ClientContext ctx;
        ctx.AddMetadata("authorization", "Bearer " + active_jwt_token_);
        HeartbeatResponse resp;
        grpc::Status status = stub_->SubmitHeartbeat(&ctx, hb, &resp);

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}
```
```

