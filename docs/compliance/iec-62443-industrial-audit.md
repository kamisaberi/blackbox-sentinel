# IEC 62443-3-3 Industrial Audit & Certification Guide

The **IEC 62443** standard defines cybersecurity requirements for Industrial Automation and Control Systems (IACS). `blackbox-sentinel` operates as an inline active security appliance designed to satisfy **Security Level 3 (SL 3)** and **Security Level 4 (SL 4)** requirements under **IEC 62443-3-3**.

---

## 1. Foundational Requirements (FR) Traceability

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ IEC 62443-3-3 System Security Compliance Architecture       │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ FR 3: SYSTEM  │       │ FR 5: ZONE    │       │ FR 7: RESOURCE│
 │   INTEGRITY   │       │ SEGMENTATION  │       │  AVAILABILITY │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         ▼                       ▼                       ▼
 SR 3.1 Comm Integrity   SR 5.1 Conduit Segment  SR 7.1 DoS Protection
 SR 3.5 Input Validation SR 5.2 Boundary Filter  SR 7.2 Zero-SKB Alloc
 (Modbus / S7 / DNP3)    (In-Kernel eBPF Drops)  (Line-Rate Resilience)
```

---

## 2. Technical System Requirements (SR) Mappings

### FR 3: System Integrity
* **SR 3.1 (Communication Integrity):** Subsystem `18_cps_sec` and protocol dissectors parse industrial payloads in real time, validating that control instructions have not been altered or replayed.
* **SR 3.5 (Input Validation):** All incoming industrial protocol frames (Modbus, DNP3, Profinet, Ethernet/IP) undergo strict bounds checking before reaching field PLCs, preventing malformed packet attacks from destabilizing legacy firmware.

### FR 5: Restricted Data Flow (Zone Boundary Protection)
* **SR 5.1 (Network Segmentation):** The appliance sits on the boundary between Purdue Model Level 3 (Operations / SCADA DMZ) and Level 1/2 (Control / Field Devices), enforcing strict unidirectional and protocol-conforming conduit policies.
* **SR 5.2 (Zone Boundary Protection):** Enforces microsecond packet drop policies directly in the NIC driver ring via `xdp_filter.o`, isolating compromised workstations from field buses.

### FR 7: Resource Availability
* **SR 7.1 (Denial of Service Protection):** Protects field controllers from volumetric flood attacks by executing in-kernel drops ($< 0.84\,\mu\text{s}$) without exhausting operating system memory buffers.
* **SR 7.2 (Resource Management):** Operates within a bounded, pre-allocated memory envelope ($< 2.0\text{ GB}$), preventing daemon crashes under sustained traffic loads.

---

## 3. Extracting the Auditor Verification Report

Generate an IEC 62443 audit bundle via CLI:

```bash
sudo sentinel --audit --standard IEC62443-3-3 --output /var/log/sentinel/iec62443_audit.json
```

Verify that the report validates all active conduit policies:

```bash
jq '.compliance_summary' /var/log/sentinel/iec62443_audit.json
```

### Expected Output
```json
{
  "standard": "IEC 62443-3-3",
  "target_security_level": "SL 3 / SL 4",
  "fr3_system_integrity": "COMPLIANT (Active Dissectors: 8)",
  "fr5_zone_segmentation": "COMPLIANT (eBPF Boundary Filter Active on eth1)",
  "fr7_resource_availability": "COMPLIANT (Zero-SKB Allocation Active)",
  "audit_status": "PASSED"
}
```

