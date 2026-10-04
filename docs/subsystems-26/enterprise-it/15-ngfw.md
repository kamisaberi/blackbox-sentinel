---

### File: `blackbox-sentinel/docs/subsystems-26/enterprise-it/15-ngfw.md`

```markdown
# Subsystem 15: Next-Generation Firewall (`15_ngfw`)

`15_ngfw` provides Layer 7 application identification and stateful protocol tracking. It classifies sessions based on behavioral heuristics and protocol handshakes rather than relying on port numbers alone.

---

## 1. Layer 7 State Machine

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Stateful Flow Tracker (1,000,000 Concurrent Conntrack Slots)│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ TCP Three-Way │       │ L7 Protocol   │       │ Policy Check  │
 │ Handshake Val │──────►│ Classification│──────►│ (Permit, Deny,│
 │ (SYN, ACK)    │       │ (HTTP, S7, SSH│       │  Rate-Limit)  │
 └───────────────┘       └───────────────┘       └───────────────┘
```

---

## 2. Port Agnostic Identification

If an adversary routes an SSH tunnel over port 80 or runs a Modbus master over port 443, `15_ngfw` identifies the protocol mismatch within the first 3 packets of the data exchange and enforces security policy overrides.
```

