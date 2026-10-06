# Subsystem 19: Sovereign Web Gateway & Egress Filter (`19_swg`)

`19_swg` enforces sovereign outbound data sovereignty policies. It monitors and restricts outbound connections from local edge devices to the internet, enforcing DNS-over-HTTPS sinkholing, TLS certificate validation, and zero cloud data egress invariants.

---

## 1. Outbound Egress Enforcement Architecture

```text
 [ Protected Subnet Device (PLC / Medical Modality / Gateway) ]
                            │
                            ▼ Outbound Request (e.g. TCP 443 / UDP 53)
 ┌─────────────────────────────────────────────────────────────┐
 │ 19_swg Sovereign Proxy Engine                               │
 └──────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
 ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
 │ DNS Filtering│    │ TLS Cert Pin │    │ Zero Egress  │
 │ Blocks DGA & │    │ Traps Rogue  │    │ Blocks Cloud │
 │ C2 Domains   │    │ MITM Proxies │    │ Data Exfil   │
 └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │ Violation Detected
                            ▼
 [ In-Kernel XDP_DROP on Egress: Zero Bytes Leave the Plant ]
```

---

## 2. Invariants

* **Deterministic Sinkholing:** Unauthorized external DNS queries are redirected to `127.0.0.1` in driver space.
* **$0.00 Egress Enforcement:** Enforces strict boundary policies preventing connected devices from pushing telemetry to unapproved public cloud endpoints.

