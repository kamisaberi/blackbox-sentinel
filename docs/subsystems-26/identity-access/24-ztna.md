---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/24-ztna.md`

```markdown
# Subsystem 24: Dynamic Zero Trust Session Risk Regressor (`24_ztna`)

`24_ztna` replaces static perimeter authentication with continuous, real-time trust evaluation. It calculates a continuous session risk score ($R \in [0.0, 1.0]$) for every active connection, updating dynamically with every network frame.

---

## 1. Dynamic Risk Regression Formula

$$R(t) = w_{\text{endpoint}} \cdot S_{\text{EDR}} + w_{\text{network}} \cdot S_{\text{NDR}} + w_{\text{identity}} \cdot S_{\text{ITDR}} + w_{\text{anomaly}} \cdot S_{\text{AI}}$$

```text
 Continuous Frame Ingress
            │
            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Real-Time Risk Regressor (Evaluated every 100ms)            │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   R < 0.30                0.30 <= R < 0.70             R >= 0.70
 ┌───────────────┐       ┌───────────────────┐   ┌───────────────────┐
 │ LOW RISK      │       │ ELEVATED RISK     │   │ CRITICAL RISK     │
 │ Fully Trusted │       │ Enforce Step-Up   │   │ Immediate Session │
 │ Access        │       │ MFA Challenge     │   │ Revocation / Drop │
 └───────────────┘       └───────────────────┘   └───────────────────┘
```

---

## 2. Continuous Policy Enforcement

If an authenticated engineering workstation begins issuing unexpected Modbus write commands, $S_{\text{anomaly}}$ increases, driving the composite risk score $R(t)$ past $0.70$. `24_ztna` terminates the session and resets the TCP connection via `XDP_TX` without waiting for token expiration.
```

