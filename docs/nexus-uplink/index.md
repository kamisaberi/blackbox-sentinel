# Sentinel-Nexus Fleet Uplink

`NexusUplink` (`src/nexus/NexusUplink.cpp`) manages bidirectional gRPC communication (port 50051) between the edge appliance and `sentinel-nexus`.

## Section Navigation

- [Uplink Architecture](./uplink-architecture.md): Background client thread model, fault isolation, and mTLS 1.3 encryption.
- [Hardware Enrollment Flow](./hardware-enrollment-flow.md): TPM 2.0 PCR quote handshake protocol (`sentinel_nexus.proto`).
- [Telemetry & Heartbeats](./telemetry-and-heartbeats.md): 5-second metric harvest loop and 4-tier asset hierarchy mapping.
- [Collective Defense Sync](./collective-defense-sync.md): Sub-50ms rule propagation ("Attacked Once, Immune Everywhere").
- [Kernel Drop Injector](./kernel-drop-injector.md): Direct `bpf()` system call bridge mutating `blocked_ip_map`.
- [OTA Model Updates](./ota-model-updates.md): Staged canary model deployment and zero-downtime hot reloads.
- [Instant Graceful Disconnect](./instant-graceful-disconnect.md): Instant 0ms process deregistration on signal traps.
