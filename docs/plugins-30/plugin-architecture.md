# Plugin Architecture

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Dynamic loading, ABI versioning, and zero-allocation parsing for all 30 dissectors.

## Loading

dlopen with RTLD_LOCAL; ABI pins reject mismatched builds at load.

## Parsing

Zero-allocation field walks; no per-packet heap on any dissector path.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
