# Kernel Drop Injector

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Direct kernel BPF syscall mapping (KernelDropInjector.cpp).

## Mapping

One bpf_map_update_elem per rule; batched under burst load.

## Audit

Every injection logs rule provenance for the console.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
