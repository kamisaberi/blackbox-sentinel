# systemd Service Tuning

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Real-time priorities (SCHED_RR), nice levels, and capabilities.

## Priority

SCHED_RR at priority 80 with nice -10 for verdict threads.

## Capabilities

CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF ambient; everything else dropped.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
