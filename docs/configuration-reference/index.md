# Configuration Reference

Complete technical specifications for configuration manifests, subsystem tuning parameters, and systemd service units.

## Section Navigation

- [sentinel.yaml Specification](./sentinel-yaml-specification.md): Exhaustive YAML configuration manifest documentation.
- [Module Tuning Parameters](./module-tuning-parameters.md): Sizing state matrix memory budgets across all 26 subsystems.
- [SCADA Safety Thresholds](./scada-safety-thresholds.md): Defining industrial physical invariants in `18_cps_sec`.
- [Environment Variables](./environment-variables.md): Runtime environment variable overrides.
- [systemd Service Tuning](./systemd-service-tuning.md): Production systemd unit file with real-time scheduling (`SCHED_RR`).
