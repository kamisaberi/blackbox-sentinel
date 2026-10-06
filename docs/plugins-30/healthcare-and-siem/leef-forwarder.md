# Log Event Extended Format (LEEF) Forwarder (`libsentinel_plugin_leef.so`)

The LEEF Forwarder transforms security telemetry into **IBM QRadar Log Event Extended Format (LEEF 1.0 / 2.0)** structures, enabling integration with IBM QRadar SIEM instances.

---

## 1. LEEF 2.0 Specification

```text
LEEF:2.0|Aryorithm|Blackbox-Sentinel|2.4.0|RuleID|Delimiter|Key=Value<delim>Key=Value...
```

### Formatted Example:
```text
LEEF:2.0|Aryorithm|Blackbox-Sentinel|2.4.0|1802|^|src=198.51.100.42^dst=10.240.0.100^srcPort=44120^dstPort=502^mitigationAction=XDP_DROP^kernelDropLatency=0.82
```

---

## 2. Configuration (`sentinel.yaml`)

```yaml
forwarders:
  leef:
    enabled: true
    destination_host: "10.240.0.50"
    destination_port: 514
    protocol: "TCP" # TCP, UDP, or TLS
    delimiter: "^"
    batch_size: 100
```

