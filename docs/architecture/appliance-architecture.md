# Decoupled C++20 Appliance Engine Design & Orchestration

`blackbox-sentinel` is designed as a modular, low-overhead appliance daemon (`sentinel`) that coordinates 26 native security subsystems and 30 industrial protocol dissectors without monolithic lock contention or inter-service IPC serialization.

---

## 1. High-Level Subsystem Layout

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                      ApplianceCore Orchestrator                             │
 │   - Signal Handlers (SIGINT/SIGTERM 0ms Disconnect)                         │
 │   - ConfigManager (/etc/sentinel/sentinel.yaml Parser)                      │
 │   - LicenseManager (TPM 2.0 PCR-Sealed Entitlements)                        │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
 ┌──────────────────────────┐    ┌──────────────────────────┐    ┌──────────────────────────┐
 │ Enterprise IT & Web Sec  │    │ Host, Workload & Binary  │    │ Cyber-Physical OT & Foren│
 │ • 01 SIEM Core           │    │ • 06 EDR Process Tree    │    │ • 17 IoT (DICOM/HL7)     │
 │ • 02 UEBA Analytics      │    │ • 07 EPP/NGAV Entropy    │    │ • 18 CPS SCADA Validator │
 │ • 03 NDR TLS Fingerprint │    │ • 09 CWPP Syscall BPF    │    │ • 21 Side-Channel Power  │
 │ • 04 IDS/IPS Engine      │    │ • 16 CDR Macro Stripper  │    │ • 22 DFIR PCAP Carver    │
 │ • 05 WAF / 10 BAD / 11 RASP│  │ • 20 FSE Firmware Check  │    │ • 26 DDP Deception Decoys│
 └──────────────────────────┘    └──────────────────────────┘    └──────────────────────────┘
        │                               │                               │
        └───────────────────────────────┼───────────────────────────────┘
                                        │ Non-blocking In-Memory Event Bus
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     Foundational Shared Runtimes                            │
 │  [Tier 2 libblackbox.so: eBPF/XDP Drop]  [Tier 1 libxinfer.so: Zero-Copy AI]│
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Decoupled Subsystem Lifecycle (`ISubsystem`)

Every subsystem implements a standardized C++20 interface enforcing strict isolation:

```cpp
#pragma once

#include <string_view>
#include <memory>

namespace sentinel {

enum class SubsystemState {
    UNINITIALIZED,
    CONFIGURED,
    RUNNING,
    DEGRADED,
    STOPPED
};

class ISubsystem {
public:
    virtual ~ISubsystem() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual uint32_t subsystem_id() const noexcept = 0;

    virtual void configure(const SubsystemConfig& config) = 0;
    virtual void start() = 0;
    virtual void stop() noexcept = 0;

    [[nodiscard]] virtual SubsystemState state() const noexcept = 0;
    [[nodiscard]] virtual SubsystemHealth check_health() = 0;
};

} // namespace sentinel
```

---

## 3. Fault Isolation & Crash Trapping

If an individual subsystem experiences an unhandled internal error (e.g., an unexpected state in a proprietary parser):
1. **Isolated Context:** Subsystem worker threads run within dedicated exception boundaries.
2. **Graceful Degradation:** The orchestrator transitions the faulty subsystem to `SubsystemState::DEGRADED` while the remaining 25 subsystems continue evaluating traffic.
3. **Automated Recovery:** The orchestrator drains the affected module's input ring and re-instantiates its execution context without restarting the host daemon or dropping in-kernel eBPF network hooks.

