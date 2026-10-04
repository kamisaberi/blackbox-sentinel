# 09_cwpp

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Container eBPF syscall breakout guard at sys_enter. Domain: Host, Workload & Binary.

## Responsibility

Container eBPF syscall breakout guard at sys_enter. Operates within the unidirectional pipeline and reports telemetry to the supervisor.

## Tuning

Thresholds, timeouts, and state sizing live under subsystems.09 in sentinel.yaml; changes apply without reboot.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
