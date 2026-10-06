# Inline Active Protection for Industrial PLCs (Modbus & Siemens S7)

This tutorial guides you through placing `blackbox-sentinel` inline as a transparent active defense bridge between an engineering workstation and a Schneider Modicon M340 / Siemens S7 PLC, enforcing sub-microsecond in-kernel drops against unauthorized register mutations.

---

## 1. Inline Physical Bridge Architecture

```text
 [ SCADA Engineering Workstation ]
                │
                ▼ Ingress Cable
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Hardware Appliance (Inline Bridge)        │
 │  - Ingress: eth1 | Egress: eth2                             │
 │  - 18_cps_sec monitors register setpoints                   │
 │  - Drops out-of-bounds commands in kernel space (< 0.84 µs) │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Egress Cable
                                ▼
 [ Critical Field Controller: Schneider Electric Modicon M340 ]
```

---

## 2. Invariant Rules Configuration

Edit `/etc/sentinel/sentinel.yaml` to enforce strict boundaries on critical centrifuge registers:

```yaml
appliance:
  node_name: "substation-active-guard"
  deployment_stage: "STAGE_FULL_ACTIVE" # Enforces automated in-kernel drops

network:
  primary_interface: "eth1"
  xdp_attach_mode: "DRIVER"

subsystems:
  cps_sec:
    enabled: true
    enforce_physical_invariants: true
    industrial_invariants:
      - rule_id: 1801
        description: "Centrifuge Motor Speed Bounds"
        protocol: "MODBUS_TCP"
        unit_id: 1
        target_register: 40010
        valid_range:
          min: 500   # Minimum 500 RPM
          max: 3600  # Maximum 3600 RPM (Over-speed runaway protection)
        max_rate_of_change:
          max_delta_per_second: 300 # Traps instantaneous acceleration commands
        violation_ttl_seconds: 300
```

Restart the appliance:

```bash
sudo systemctl restart sentinel
```

---

## 3. Simulating an Attack with `mbpoll`

From an unauthorized test terminal on the network, attempt to write an out-of-bounds speed command ($9{,}999\text{ RPM}$) to register `40010`:

```bash
# Attempt unauthorized write of 9999 to register 40010
mbpoll -m tcp -a 1 -r 40010 -t 4:int 192.168.10.50 9999
```

### Expected Output

```text
Write failed: Connection timed out (or Host unreachable)
```

Check the active appliance drop table via CLI:

```bash
sentinel --dump-drops
```

### Verification Trace
```text
[!] IN-KERNEL DROP CONFIRMED:
    Source IP    : 192.168.10.99
    Triggered By : 18_cps_sec (Rule 1801: Centrifuge Motor Speed Bounds)
    Requested Val: 9999 RPM (Exceeds Max Physical Threshold 3600 RPM)
    Drop Latency : 0.81 µs (eBPF Driver Space)
    PLC Status   : Normal Operation Maintained (3,200 RPM)
```

