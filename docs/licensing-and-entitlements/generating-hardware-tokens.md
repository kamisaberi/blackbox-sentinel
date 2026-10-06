# Generating Offline Hardware Tokens (`--generate-hardware-token`)

To acquire a cryptographically bound offline license file, the plant administrator generates an anonymous hardware token on the target edge appliance and transmits it to Aryorithm via email, portal, or air-gapped staging.

---

## 1. Token Generation Command

Execute `sentinel` with the hardware token argument:

```bash
sentinel --generate-hardware-token
```

### Sample Output

```text
================================================================================
              BLACKBOX-SENTINEL HARDWARE IDENTIFICATION TOKEN
================================================================================
Appliance Architecture : x86_64-linux-gnu
Platform Root of Trust : TIER 1 (Discrete Physical TPM 2.0 Silicon)
Manufacturer ID        : IFX (Infineon Technologies)

--------------------------- COPY TOKEN BELOW THIS LINE -------------------------
HWT-01-IFX-8A2F3C1E42C994B1-D41D8CD98F00B204E9800998ECF8427E-PCR0-E9A2C31E
--------------------------- COPY TOKEN ABOVE THIS LINE -------------------------

Instructions:
1. Copy the token string above.
2. Submit this token to portal.aryorithm.com or your licensing representative.
3. You will receive an offline, cryptographically signed license.lic envelope.
================================================================================
```

---

## 2. Hardware Token Composition

The hardware token string encodes four hardware elements:

$$\text{Token} = \text{TIER} \parallel \text{MFG} \parallel \text{TPM\_UUID} \parallel \text{DMI\_HASH} \parallel \text{PCR0\_DIGEST}$$

* **Tier Descriptor (`TIER 1` / `TIER 2` / `TIER 3`):** Declares whether the underlying cryptoprocessor is physical silicon, a virtual vTPM, or a DMI fallback.
* **Manufacturer ID (`IFX`, `STM`, `NTC`):** Semiconductor manufacturer tag.
* **TPM Unique Identifier:** Derived from the physical TPM Endorsement Key public exponent.
* **PCR 0 Digest:** Cryptographic measurement of the motherboard BIOS and microcode.

