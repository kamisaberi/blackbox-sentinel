# Subsystem 20: Firmware Security Evaluation (`20_fse`)

`20_fse` inspects the appliance's underlying motherboard UEFI/BIOS SPI flash chip, Option ROMs, and PCIe peripheral firmware. It verifies hardware firmware integrity against cryptographically signed manufacturer baselines.

---

## 1. Physical Firmware Audit Pipeline

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Direct SPI Controller Access (/dev/mem / MTD driver)        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ UEFI Firmware Volume (FV) Dissector                         │
 │   - Traverses Firmware File System (FFS) headers            │
 │   - Extracts PE32/TE EFI drivers and DXE executables        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ SHA-256 Hash  │       │ Verify Secure │       │ Compare with  │
 │ Extraction    │       │ Boot db/dbx   │       │ TPM 2.0 PCR 0 │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
 [ Detects Rootkits, MoonBounce, CosmicStrand, and BlackLotus ]
```

---

## 2. TPM 2.0 PCR 0 Cryptographic Sealing

`20_fse` cross-checks extracted firmware digests against **TPM 2.0 PCR 0**:
* If an unauthorized SPI flash write occurs, the physical PCR 0 digest will not match the manufacturer quote.
* The appliance enters **`STAGE_FORENSIC_LOCKDOWN`**, refusing to unseal cryptographic storage keys.

