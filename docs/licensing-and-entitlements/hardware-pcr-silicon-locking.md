# Binding Licenses to Physical TPM 2.0 PCR 0 Measurements

To prevent enterprise license files from being cloned across unbilled virtual machines or duplicated edge appliances, `blackbox-sentinel` binds licenses directly to the host's **physical TPM 2.0 Platform Configuration Register 0 (PCR 0)**.

---

## 1. Silicon Binding Architecture

```text
 [ Production Appliance A (Valid) ]           [ Cloned Appliance B (Unauthorized) ]
  • Physical TPM Chip ID: 0x8A2F...           • Virtual / Cloned TPM ID: 0x1111...
  • Measured PCR 0: 0xE9A2...                 • Measured PCR 0: 0x9999... (Mismatch)
              │                                           │
              ▼                                           ▼
 ┌─────────────────────────────┐             ┌─────────────────────────────┐
 │ License Verification: OK    │             │ License Verification: FAILS │
 │ Unlocks Enterprise Modules  │             │ Drops to Community Edition  │
 └─────────────────────────────┘             └─────────────────────────────┘
```

---

## 2. Cryptographic Validation Mechanics

When `LicenseManager` evaluates `locked_hardware_digest`:
1. It queries `/dev/tpmrm0` via the TSS2 API to read the current hardware PCR 0 digest.
2. It hashes the hardware manufacturer ID, the TPM Endorsement Public Key, and the active PCR 0 value.
3. It performs a constant-time comparison (`CRYPTO_memcmp`) against the signed claim inside `license.lic`.
4. If a user duplicates the hard drive or VM image to another server, the new host's physical TPM chip will produce a divergent digest, automatically downgrading the clone to Community Edition.

