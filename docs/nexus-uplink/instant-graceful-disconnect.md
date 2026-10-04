# Instant Graceful Disconnect

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


0ms DeregistrationRequest dispatch upon SIGINT/Ctrl+C.

## Signal

SIGINT handler emits the frame before teardown begins.

## Effect

Nexus marks OFFLINE in 0ms — no 15-second timeout.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
