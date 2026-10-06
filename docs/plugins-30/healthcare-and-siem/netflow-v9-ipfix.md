# NetFlow v9 & IPFIX Flow Telemetry Exporter (`libsentinel_plugin_netflow.so`)

The NetFlow v9 and IPFIX (IETF RFC 7011) exporter aggregates continuous packet flows into directional flow records, streaming them to network visibility collectors over UDP port **2055 or 4739**.

---

## 1. IPFIX Template Architecture

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ IPFIX Message Header (Version 0x000A, Length, Sequence No)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Template Record (Set ID 2)                    ▼ Data Record (Set ID 256)
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Declares Information Element│         │ Flow Values:                │
 │ Types:                      │         │  • sourceIPv4Address        │
 │  • IE 8: sourceIPv4Address  │         │  • destinationIPv4Address   │
 │  • IE 12: destinationIPv4   │         │  • octetDeltaCount          │
 │  • IE 1: octetDeltaCount    │         │  • packetDeltaCount         │
 │  • IE 2: packetDeltaCount   │         │  • flowStartNanoseconds     │
 └─────────────────────────────┘         └─────────────────────────────┘
```

---

## 2. Sustained Line-Rate Export

* Aggregates up to **$2{,}500{,}000\text{ flows/minute}$** within a $32\text{ MB}$ memory footprint.
* Implements template cycling every $600\text{ seconds}$ to satisfy collector state refreshes.

