# Appliance Architecture

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Decoupled C++20 engine design and multi-subsystem orchestration.

## Decoupling

26 modules share lock-free interfaces; a fault in one cannot stall the verdict path.

## Orchestration

A supervisor restarts failed modules without touching the kernel filter.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
