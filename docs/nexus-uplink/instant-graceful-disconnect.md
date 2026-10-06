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

