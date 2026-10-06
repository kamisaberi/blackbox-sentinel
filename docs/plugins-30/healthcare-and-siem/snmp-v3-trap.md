# SNMPv3 Encrypted Operational Trap Forwarder (`libsentinel_plugin_snmp.so`)

The SNMPv3 Trap forwarder alerts legacy Operations Technology (OT) Network Management Systems (NMS)—such as **Cisco Prime, SolarWinds, and Hirschmann Industrial HiVision**—via authenticated and encrypted SNMPv3 Inform and Trap PDUs on UDP port **162**.

---

## 1. Security Architecture (USM Model)

SNMPv3 enforces User-based Security Model (USM) specifications:
* **Authentication:** HMAC-SHA-256 (`usmHMACSHAAuthProtocol`).
* **Privacy / Encryption:** AES-128 CFB (`usmAesCfb128Protocol`).
* **Authoritative Engine ID:** Derived directly from the appliance's physical TPM 2.0 unique identifier, preventing trap replay attacks.

---

## 2. Enterprise MIB Topology (`ARYORITHM-BLACKBOX-MIB`)

```text
 1.3.6.1.4.1.59999 (iso.org.dod.internet.private.enterprises.aryorithm)
  └── .1 (blackboxSentinel)
       ├── .1.1 (trapThreatMitigated)
       │    ├── .1.1.1 (threatRuleId)
       │    ├── .1.1.2 (threatSourceIP)
       │    ├── .1.1.3 (threatMitigationLatency)
       │    └── .1.1.4 (threatAction)
       └── .1.2 (trapHardwareTamperAlarm)
```

