# Enterprise Support SLAs & Incident Escalation

---

## 1. Automated Diagnostic Bundle Generation

When reporting an issue, generate an automated, sanitized diagnostic bundle:

```bash
sudo sentinel --diag-bundle --output /tmp/sentinel_diagnostic_bundle.tar.gz
```

This bundle packages:
* `/etc/sentinel/sentinel.yaml` (With credentials and keys automatically sanitized).
* Active systemd service journal logs (last 500 lines).
* Kernel eBPF program and map listings (`bpftool prog show`, `bpftool map show`).
* TPM 2.0 silicon status and hardware driver capabilities.

---

## 2. Enterprise Commercial Support SLAs

Aryorithm Technologies B.V. provides commercial support for defense and critical infrastructure networks:

| Support Tier | Target Response Time | Availability | Scope |
| :--- | :--- | :--- | :--- |
| **Standard Support** | 8 Business Hours | Mon–Fri 08:00–18:00 CET | Configuration review, updates, bug patches. |
| **Mission-Critical Defense** | **1 Hour (24/7/365)** | Round-the-Clock | Dedicated systems architect, kernel-level triage, custom OT dissector engineering, on-site support. |

For technical inquiries and enterprise SLA contracts:
* **Customer Portal:** `https://app.aryorithm.com/support`
* **Email:** `support@aryorithm.com`

---

## 3. Coordinated Vulnerability Disclosure

If you identify a potential security bypass or memory safety vulnerability in `blackbox-sentinel`:
* Send an encrypted PGP message to **`security@aryorithm.com`**.
* We acknowledge disclosures within **48 hours** and provide CVE assignment, risk remediation, and backported security patches according to coordinated disclosure guidelines.

