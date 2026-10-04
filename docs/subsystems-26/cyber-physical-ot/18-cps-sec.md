---

### File: `blackbox-sentinel/docs/subsystems-26/cyber-physical-ot/18-cps-sec.md`

```markdown
# Subsystem 18: SCADA Physical Constraint Validator (`18_cps_sec`)

`18_cps_sec` bridges cyber defense with the laws of physical thermodynamics. It models industrial physical invariants (e.g., turbine RPM velocities, pipeline pressures, chemical dosing limits) and parses industrial protocol frames (**Modbus TCP, DNP3, Siemens S7Comm**) to drop out-of-bounds commands before they reach physical field actuators.

---

## 1. Physical Invariant Enforcement Model

Attackers (such as the authors of Stuxnet, Industroyer, or Triton) craft syntactically valid protocol frames with values designed to cause physical destruction. `18_cps_sec` verifies commands against **thermodynamic state equations**:

$$\Delta V = \frac{V_{\text{target}} - V_{\text{current}}}{t - t_{\text{last}}} \le \text{MaxAllowableRateOfChange}$$

```text
 [ Ingress Modbus TCP Packet: Function Code 16 (Write Registers) ]
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Protocol APDU Dissection                                    │
 │   - Target Register: 40001 (Main High-Pressure Gas Valve)   │
 │   - Requested Value: 9,850 PSI                              │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Physical Invariant Check
 ┌─────────────────────────────────────────────────────────────┐
 │ State Validator (18_cps_sec)                                │
 │   - Current Pressure   : 2,100 PSI                          │
 │   - Max Physical Bound : 4,500 PSI                          │
 │   - Calculated Gradient: +7,750 PSI / 100ms (Illegal Slope) │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ VIOLATION DETECTED
 [ In-Kernel XDP Drop Triggered: Dropped before PLC (< 0.84 µs) ]
```

---

## 2. Cumulative Actuator Wear & Cycle Counter

To prevent high-frequency mechanical wear attacks, `18_cps_sec` tracks cumulative actuator cycles:

```cpp
#include <cstdint>
#include <chrono>

namespace sentinel::subsystems {

struct ActuatorWearTracker {
    uint32_t register_id{0};
    uint64_t total_cycles{0};
    uint64_t max_duty_cycles_per_hour{100};
    uint64_t cycles_this_hour{0};
    uint64_t last_cycle_time_ns{0};

    bool record_actuation(uint64_t now_ns) noexcept {
        // Enforce minimum physical refractory period (e.g. 500ms between valve shifts)
        if (now_ns - last_cycle_time_ns < 500'000'000ULL) {
            return false; // Physical cycling rate exceeded
        }

        last_cycle_time_ns = now_ns;
        total_cycles++;
        cycles_this_hour++;
        return cycles_this_hour <= max_duty_cycles_per_hour;
    }
};

} // namespace sentinel::subsystems
```

---

## 3. Configuration Schema (`sentinel.yaml`)

```yaml
subsystems:
  cps_sec:
    enabled: true
    industrial_invariants:
      - protocol: "MODBUS"
        unit_id: 1
        register: 40001
        min_value: 0.0
        max_value: 4500.0
        max_rate_of_change_per_sec: 150.0
        on_violation: "KERNEL_DROP"
```
```

