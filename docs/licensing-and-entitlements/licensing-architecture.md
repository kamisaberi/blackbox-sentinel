# Asymmetric Cryptographic Licensing Architecture

In air-gapped industrial, healthcare, and defense networks, security software cannot phone home to cloud license servers or validate activation keys over the internet. 

`blackbox-sentinel` enforces an **Asymmetric Cryptographic Licensing Model**. Licenses are issued as signed cryptographic envelopes verified entirely on-premises using embedded public keys with **$0.00 cloud data egress**.

---

## 1. Asymmetric Verification Model

```text
 [ ARYORITHM AIR-GAPPED LICENSING CA (Offline Master Vault) ]
                              │
                              ▼ Signs License Envelope with Private Key (Ed25519 / RSA-4096)
 ┌─────────────────────────────────────────────────────────────┐
 │ Cryptographic License File: /etc/sentinel/license.lic        │
 │  - Base64 Encoded JSON Payload + Ed25519 Digital Signature  │
 │  - Encapsulates: Tenant ID, Expiration Date, Entitled IDs,  │
 │    and Locked Hardware Silicon Digest (TPM PCR 0 + DMI)     │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼ Transferred via Secure USB / Air-Gapped Staging
 ┌─────────────────────────────────────────────────────────────┐
 │ Edge Appliance: blackbox-sentinel (LicenseManager.hpp)      │
 │  - Verifies Signature using In-Process Embedded Public Key  │
 │  - Computes Local Hardware Token & PCR 0 Measurement        │
 │  - Matches Entitled Subsystems (5 Free vs. 26 Enterprise)   │
 └────────────────────────────┬────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        ▼ VALID LICENSE                             ▼ TAMPERED / EXPIRED / WRONG CHIP
 ┌───────────────────────────┐               ┌───────────────────────────┐
 │ Activates Entitled Engine │               │ Drops to Community Mode   │
 │ Modules & Dissectors      │               │ (5 Core Modules Only)     │
 └───────────────────────────┘               └───────────────────────────┘
```

---

## 2. Cryptographic Envelopes

A `blackbox-sentinel` license file (`license.lic`) consists of two distinct sections:

1. **Payload (JSON):** Plaintext operational claims declaring customer name, license tier, allowed network throughput (e.g., $10\text{ GbE}$ line-rate), subsystem bitmask, and locked hardware digest.
2. **Signature (Cryptographic Envelope):** A 64-byte Ed25519 digital signature generated over the canonical JSON string by Aryorithm’s offline certificate authority.

---

## 3. Air-Gapped Invariants

* **Zero Phoning Home:** The daemon never initiates outbound DNS requests, HTTP activations, or heartbeat pings to verify licenses.
* **Deterministic Clock Tamper Trapping:** Prevents rollback attacks by recording the latest observed monotonic timestamp into TPM non-volatile RAM. If system time regresses behind the latest recorded timestamp, the license engine flags clock tampering.

