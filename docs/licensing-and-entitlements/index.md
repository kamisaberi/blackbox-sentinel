# Licensing & Entitlements

`blackbox-sentinel` enforces an asymmetric cryptographic licensing model verified 100% on-premises with $0.00 cloud data egress.

## Section Navigation

- [Licensing Architecture](./licensing-architecture.md): Asymmetric Ed25519 digital signature validation.
- [LicenseManager Engine](./license-manager-engine.md): In-process entitlement gatekeeping (`LicenseManager.hpp`).
- [Community vs. Enterprise](./community-vs-enterprise.md): Entitlement matrix comparing Community Edition (5 modules) to Enterprise OT (26 modules).
- [Generating Hardware Tokens](./generating-hardware-tokens.md): Offline token generation (`--generate-hardware-token`).
- [Applying License Envelopes](./applying-license-envelopes.md): Installing `license.lic` and executing live SIGHUP reloads.
- [Hardware PCR Silicon Locking](./hardware-pcr-silicon-locking.md): Binding licenses to physical TPM 2.0 PCR 0 measurements.
