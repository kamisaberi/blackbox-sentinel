# EU NIS 2 Directive: Article 21 Compliance & $0.00 Cloud Egress

The European Union **NIS 2 Directive (Directive (EU) 2022/2555)** establishes strict risk management and incident response mandates for essential and important entities across energy, water, healthcare, and transport sectors.

`blackbox-sentinel` is architected for complete compliance with **Article 21**, operating 100% on-premises with **$0.00 cloud data egress**.

---

## 1. Traceability to Article 21 Risk-Management Measures

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ NIS 2 Directive: Article 21 Technical Alignment             │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ Art 21(2)(b)  │       │ Art 21(2)(c)  │       │ Art 21(2)(d)  │
 │ Incident      │       │ Business      │       │ Supply Chain  │
 │ Handling      │       │ Continuity    │       │ Security      │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         ▼                       ▼                       ▼
 Sub-Microsecond Edge    Zero-SKB Allocation     TPM 2.0 Hardware
 Mitigation (< 0.84 µs)  resists volumetric      Root verifies boot
 Traps zero-day threats. network floods.         firmware integrity.
```

---

## 2. The $0.00 Cloud Egress Invariant

Under NIS 2 Article 21(2)(a), organizations must maintain rigorous information system security policies. Transmitting unencrypted SCADA or healthcare telemetry across international cloud infrastructures introduces compliance risks and third-party data processing liabilities under EU GDPR.

`blackbox-sentinel` enforces local execution:
* **All 26 Subsystems run on-premises** on bare-metal appliance hardware.
* **Zero telemetry frames leave the local perimeter** unless explicitly configured to push filtered event summaries to `sentinel-nexus`.
* Cloud data egress costs remain **$0.00** permanently.

---

## 3. Article 23 Incident Notification Export

Under NIS 2 Article 23, organizations must submit an early warning to national CSIRTs within **24 hours** of becoming aware of a significant incident.

Generate an automated NIS 2 Early Warning Report:

```bash
sudo sentinel --export-nis2-report --incident-id 14022 --output /var/log/sentinel/nis2_incident_14022.json
```

The exported file contains structured event timestamps, compromised asset IDs, attack vector classifications, and containment proof ready for immediate submission to national authorities.

