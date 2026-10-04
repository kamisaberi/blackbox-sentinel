# Collective Defense Sync

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Receiving FleetDefenseRule and injecting eBPF maps in < 50ms.

## Fanout

Parallel gRPC broadcast; originator suppressed to avoid loops.

## Inject

KernelDropInjector programs blocked_ip_map on arrival.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
