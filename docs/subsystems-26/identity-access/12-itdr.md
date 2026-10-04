---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/12-itdr.md`

```markdown
# Subsystem 12: Identity Threat Detection & Response (`12_itdr`)

`12_itdr` inspects active Active Directory and Kerberos/LDAP authentication traffic over the wire. It detects credential attacks—including **Kerberoasting, AS-REP Roasting, DCSync, and Golden Ticket forgeries**—without requiring domain controller agent installation.

---

## 1. Kerberos Wire Inspection Mechanics

```text
 [ Ingress Kerberos TCP/UDP Port 88 Traffic ]
                       │
                       ▼ Zero-Copy ASN.1 DER Parser
 ┌─────────────────────────────────────────────────────────────┐
 │ Inspects Kerberos TGS-REQ / AS-REQ APDUs                    │
 └─────────────────────┬───────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
 [ High-Volume SPN Requests ]   [ Legacy RC4-HMAC Cipher ]
 (Service Principal Names)      (Weak encryption requested)
        │                             │
        └──────────────┬──────────────┘
                       ▼
       [ Kerberoasting Attack Confirmed ]
                       │
                       ▼ Triggers Kernel Drop
 [ Attacker Workstation IP Blocked via eBPF (< 0.84 µs) ]
```

---

## 2. Attack Vectors Detected

| Technique ID | Attack Description | Detection Heuristic |
| :--- | :--- | :--- |
| **T1558.003** | **Kerberoasting** | Spike in `TGS-REQ` packets requesting RC4 encryption (`etype 23`) across multiple SPNs. |
| **T1558.004** | **AS-REP Roasting** | `AS-REQ` requests sent for accounts with pre-authentication explicitly disabled. |
| **T1003.006** | **DCSync** | `DRSGetNCChanges` RPC call originating from a non-Domain Controller IP address. |
| **T1558.001** | **Golden Ticket** | Ticket Granting Ticket (TGT) validity timestamp exceeding the domain maximum (e.g. $> 10\text{ hours}$). |
```

