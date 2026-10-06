# Subsystem 11: Runtime Application Self-Protection (`11_rasp`)

`11_rasp` monitors the runtime memory integrity of the host daemon and co-located mission applications. It inspects process memory maps, detecting Procedure Linkage Table (PLT) hijacking, Global Offset Table (GOT) overwrites, and Return-Oriented Programming (ROP) execution chains.

---

## 1. In-Memory Hook Detection

`11_rasp` periodically audits the process memory spaces defined in `/proc/self/maps`:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Auditing Process Address Space                              │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ Check PLT/GOT │       │ Verify Shared │       │ Validate Call │
 │ Relocations   │       │ Library Hashes│       │ Stack Frames  │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Tampering Detected
                                 ▼
           [ Terminate Corrupted Context & Alert SIEM ]
```

---

## 2. Anti-Debugging & Anti-Tamper Invariants

* **`ptrace` Scope:** Automatically invokes `prctl(PR_SET_DUMPABLE, 0)` on initialization, preventing unprivileged processes from attaching debuggers or reading process memory.
* **Stack Canary Validation:** Re-verifies compiler-injected stack canaries across all high-frequency worker loops.

