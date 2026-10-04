# Telemetry & Heartbeats

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Ingesting CPU, RAM, NPU temp, drops, and sensor inventories.

## Cadence

5-second heartbeats carry counters; full inventories ride hourly deltas.

## Cost

Heartbeat payloads stay under 2 KB on the wire.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
