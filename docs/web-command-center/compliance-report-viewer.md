# On-Appliance Compliance Scorecards & Report Generation

The Web Command Center features an automated compliance audit scorecard engine that evaluates active configurations, kernel drop logs, and TPM 2.0 measurements to generate on-demand compliance reports for **IEC 62443**, **CMMC 2.0**, and **EU NIS 2**.

---

## 1. Compliance Audit Dashboard

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     GOVERNANCE & COMPLIANCE SCORECARDS                      │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ [IEC 62443-3-3 Industrial Security]                     STATUS: 100% PASS   │
 │ • FR 3 System Integrity (Input Validation / Modbus APDU)     : COMPLIANT    │
 │ • FR 5 Boundary Protection (Native In-Kernel eBPF Drops)     : COMPLIANT    │
 │ • FR 7 Resource Availability (Sub-Microsecond Zero-SKB Drop) : COMPLIANT    │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ [CMMC 2.0 / NIST SP 800-171 Level 2]                    STATUS: 100% PASS   │
 │ • SI.L2-3.14.1 Flaw Remediation (Autonomous Edge Mitigation) : COMPLIANT    │
 │ • SC.L2-3.13.1 Boundary Protection (Driver XDP Enforcement) : COMPLIANT    │
 │ • IA.L2-3.5.1 Device Authentication (Hardware TPM 2.0 Root)  : COMPLIANT    │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ [EU NIS 2 Directive - Article 21]                       STATUS: 100% PASS   │
 │ • Art 21(2)(b) Incident Handling (Sub-50ms Fleet Defense)    : COMPLIANT    │
 │ • Art 21(2)(d) Supply Chain Security (TPM PCR 0 Firmware Seal): COMPLIANT   │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ ACTIONS: [ EXPORT SIGNED PDF REPORT ]   [ DOWNLOAD RAW AUDIT JSON ]         │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Exporting Audit Reports via API

Generate signed compliance audit records directly through the command line or web console:

```bash
# Export compliance scorecard as cryptographically signed JSON bundle
curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/api/v1/compliance/export?standard=IEC62443 \
    -o iec62443_audit_evidence.json
```

---

## 3. Cryptographic Authenticity Proofs

Every exported compliance bundle includes:
1. The raw TPM 2.0 PCR 0 and PCR 4 quote generated during the audit window.
2. The SHA-256 hash chain root confirming log tamper-evidence.
3. The cryptographic signature of the local Attestation Identity Key (AIK), allowing external regulatory auditors to verify report validity without accessing internal production networks.

