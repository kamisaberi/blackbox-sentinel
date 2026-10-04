# Uplink Architecture

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Background gRPC agent architecture (src/nexus/NexusUplink.cpp).

## Agent

A dedicated thread owns the mTLS stream; verdict paths never wait on it.

## Resilience

Exponential backoff with jitter; queued frames drain on reconnect.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
