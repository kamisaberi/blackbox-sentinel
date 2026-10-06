# SCADA Physical Safety Thresholds & Invariant Rules

Subsystem `18_cps_sec` evaluates industrial protocol packets against physical thermodynamic constraints. These rules are configured under `subsystems.cps_sec.industrial_invariants`.

---

## 1. Syntax & Invariant Definition

```yaml
subsystems:
  cps_sec:
    enabled: true
    enforce_physical_invariants: true
    default_violation_action: "KERNEL_DROP" # KERNEL_DROP (<0.84µs), LOG_ONLY, ALERT_OPERATOR

    industrial_invariants:
      # ------------------------------------------------------------------------
      # Rule 101: Municipal Water High-Pressure Gas Relief Valve (Modbus)
      # ------------------------------------------------------------------------
      - rule_id: 101
        description: "Main High-Pressure Gas Valve 40001 Bounds"
        protocol: "MODBUS_TCP"
        unit_id: 1
        target_register: 40001         # 16-Bit Holding Register
        data_type: "UINT16"
        valid_range:
          min: 1000                    # Minimum allowable pressure: 1000 PSI
          max: 4500                    # Maximum allowable pressure: 4500 PSI
        max_rate_of_change:
          max_delta_per_second: 250    # Prevents water hammer / pressure spike attacks
        actuator_wear:
          max_cycles_per_hour: 60      # Prevents mechanical fatigue cycling attacks
        violation_ttl_seconds: 300     # Block attacking IP for 5 minutes

      # ------------------------------------------------------------------------
      # Rule 102: Nuclear Reactor Coolant Temperature Setpoint (Siemens S7Comm)
      # ------------------------------------------------------------------------
      - rule_id: 102
        description: "Primary Coolant Loop Temperature Bounds"
        protocol: "S7COMM"
        data_block: 1                  # DB1
        byte_offset: 12                # DB1.DBD12
        data_type: "FLOAT32"
        valid_range:
          min: 275.5                   # 275.5 Degrees Celsius
          max: 315.0                   # 315.0 Degrees Celsius
        disallow_plc_stop_command: true # Purges S7 0x29 (CPU STOP) commands
        violation_ttl_seconds: 3600    # Block attacker for 1 hour

      # ------------------------------------------------------------------------
      # Rule 103: Substation Circuit Breaker Trip Verification (DNP3)
      # ------------------------------------------------------------------------
      - rule_id: 103
        description: "High-Voltage Substation Feeder 14 Breaker Guard"
        protocol: "DNP3"
        outstation_address: 14
        permitted_function_codes: [1, 2, 3, 4] # Read & Select-Before-Operate Only
        disallow_direct_operate: true  # Blocks Function Code 05/06 (Industroyer vector)
        violation_ttl_seconds: 7200    # Block attacker for 2 hours
```

---

## 2. Invariant Evaluation Logic

When an industrial command packet arrives:
1. `18_cps_sec` extracts the target register or coil value.
2. It verifies that $\text{min} \le \text{Value} \le \text{max}$.
3. It calculates the delta velocity:
   $$\Delta v = \frac{|\text{Value}_{\text{new}} - \text{Value}_{\text{current}}|}{\Delta t}$$
4. If $\Delta v > \text{max\_delta\_per\_second}$, the packet is dropped via `XDP_DROP` in $< 0.84\,\mu\text{s}$, preventing physical damage to connected field hardware.

