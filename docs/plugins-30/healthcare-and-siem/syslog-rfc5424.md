# Structured Cryptographic Syslog Forwarder (`libsentinel_plugin_syslog.so`)

The Syslog forwarder packages events in compliance with **IETF RFC 5424 (The Syslog Protocol)**, incorporating structured metadata blocks (`[blackbox@54321 ...]`), nanosecond ISO-8601 timestamps, and TLS cryptographic transport.

---

## 1. RFC 5424 Message Layout

```text
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
```

### Sample Output:
```text
<14>1 2026-10-05T02:53:00.184920Z edge-substation-alpha sentinel 14022 SEC_DROP [blackbox@54321 ruleId="1802" action="XDP_DROP" srcIp="198.51.100.42" latencyUs="0.82"] In-Kernel eBPF mitigation executed successfully.
```

---

## 2. Structured Data Key Map

* `ruleId`: Subsystem security rule identifier.
* `action`: Action executed (`XDP_DROP`, `XDP_PASS`, `RATE_LIMIT`).
* `latencyUs`: Kernel mitigation reaction latency in microseconds.
* `tpmTier`: Hardware identity tier (`TIER1`, `TIER2`, `TIER3`).

