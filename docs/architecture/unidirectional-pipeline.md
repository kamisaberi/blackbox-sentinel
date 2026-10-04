# Unidirectional Pipeline

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Ingest → Tensor Extraction → Inference → Kernel Mitigation → Egress.

## Flow

Frames move strictly forward; there is no re-entrant path that could livelock the driver.

## Egress

Verdicts exit as drops, passes, or mirrored copies — never as callbacks into ingress.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
