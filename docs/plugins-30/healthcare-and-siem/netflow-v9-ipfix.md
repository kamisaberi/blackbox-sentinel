---

### File: `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/netflow-v9-ipfix.md`

```markdown
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
```

---

### Complete in Part 9
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/dicom-pacs.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/hl7-v2.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/cef-forwarder.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/leef-forwarder.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/syslog-rfc5424.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/kafka-producer.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/snmp-v3-trap.md`
- `blackbox-sentinel/docs/plugins-30/healthcare-and-siem/netflow-v9-ipfix.md`

All 30 Protocol Dissectors and SIEM forwarders for `blackbox-sentinel` are now documented.

---

### Files to be Generated in Part 10

The next phase covers **Nexus Uplink** (`nexus-uplink/` - 7 files):

1. `nexus-uplink/uplink-architecture.md` (Background gRPC agent architecture, `src/nexus/NexusUplink.cpp`)
2. `nexus-uplink/hardware-enrollment-flow.md` (Hardware identity probe & registration handshake)
3. `nexus-uplink/telemetry-and-heartbeats.md` (Ingesting CPU, RAM, NPU temp, drops, and sensor inventories)
4. `nexus-uplink/collective-defense-sync.md` (Receiving `FleetDefenseRule` and injecting eBPF maps in $< 50\,\text{ms}$)
5. `nexus-uplink/kernel-drop-injector.md` (Direct kernel BPF syscall mapping, `KernelDropInjector.cpp`)
6. `nexus-uplink/ota-model-updates.md` (Polling `ModelOtaService`, SHA-256 checks, and zero-downtime reloads)
7. `nexus-uplink/instant-graceful-disconnect.md` (0ms `DeregistrationRequest` dispatch upon SIGINT/Ctrl+C)

Confirm when you are ready to proceed with Part 10.