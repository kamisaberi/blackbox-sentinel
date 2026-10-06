# Securing a Hospital PACS Radiology Enclave from Exfiltration

Medical imaging environments running Picture Archiving and Communication Systems (PACS) often communicate over unencrypted DICOM streams. 

This tutorial walks through deploying `blackbox-sentinel` to protect a hospital radiology enclave from unauthorized DICOM **C-MOVE mass exfiltration** and ransomware payload injection.

---

## 1. Network Placement

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Hospital Core Switch (VLAN 40: Radiology Imaging Network)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Inline Appliance (eth0)                   │
 │  - Subsystem 17 (17_iot_sec) Active                         │
 │  - Validates Calling AE Titles & Query Velocities           │
 └──────────────┬──────────────────────────────┬───────────────┘
                │                              │
                ▼ Permitted Transfers          ▼ Unauthorized Siphoning
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │ Authorized GE CT Scanner    │ │ Rogue Laptop / Exfiltration │
 │ AET: "CT_SCANNER_01"        │ │ AET: "ROGUE_CLIENT"         │
 │ (C-STORE Allowed)           │ │ (DROPPED AT WIRE SPEED)     │
 └─────────────────────────────┘ └─────────────────────────────┘
```

---

## 2. Configuring DICOM Protection Rules

Configure Subsystem `17_iot_sec` in `/etc/sentinel/sentinel.yaml`:

```yaml
subsystems:
  iot_sec:
    enabled: true
    dicom_protection:
      enforce_aet_whitelist: true
      authorized_calling_aets:
        - "CT_SCANNER_01"
        - "MRI_SIEMENS_02"
        - "PACS_CENTRAL_SRV"
      max_c_move_queries_per_minute: 20 # Traps automated bulk exfiltration
      block_unknown_transfer_syntax: true # Drops non-standard executable payloads
      violation_action: "KERNEL_DROP"
      violation_ttl_seconds: 600
```

---

## 3. Testing with `dcmtk` Tools

Simulate an unauthorized client attempting a bulk record harvest using the `movescu` utility:

```bash
# Querying records using an unregistered AE Title
movescu -v -aet UNKNOWN_RESEARCH -aec PACS_CENTRAL_SRV 10.240.0.100 104 -k PatientName="*"
```

### Result
The initial `A-ASSOCIATE-RQ` packet is parsed in memory. Because `UNKNOWN_RESEARCH` is not whitelisted, `17_iot_sec` commands Tier 2 `libblackbox` to block the attacker's IP:

```text
[!] DICOM SECURITY BREACH:
    Source IP    : 10.240.0.88
    Calling AET  : UNKNOWN_RESEARCH (Unauthorized)
    Operation    : Bulk Patient Query (C-MOVE)
    Mitigation   : Source IP blocked in kernel for 600s. Exfiltration neutralized.
```

