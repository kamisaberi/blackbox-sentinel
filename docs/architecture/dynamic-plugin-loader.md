# Dynamic Plugin Loader

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


dlopen(RTLD_LAZY | RTLD_LOCAL) mechanics and symbol isolation.

## Loading

Dissectors load as isolated namespaces; version pins reject ABI drift.

## Isolation

-fvisibility=hidden keeps third-party symbols out of the global table.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
