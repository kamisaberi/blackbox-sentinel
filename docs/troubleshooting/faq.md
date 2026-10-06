# Technical Frequently Asked Questions (FAQ)

---

### Q1: Does `blackbox-sentinel` require an active internet connection?
**No.** `blackbox-sentinel` is designed for sovereign, air-gapped deployments. All 26 subsystems, 30 protocol dissectors, and local SIEM indexing engines execute 100% on-premises with **$0.00 cloud data egress**. It functions indefinitely without external DNS or internet access.

---

### Q2: What happens if the central `sentinel-nexus` hub goes down?
The edge appliance operates with full local autonomy:
* In-kernel packet mitigation ($< 0.84\,\mu\text{s}$) continues uninterrupted.
* Local SIEM log correlation and web command center management remain operational.
* Emitted telemetry and forensic PCAP files are buffered in local circular memory until the Nexus connection is restored.

---

### Q3: How does the appliance maintain $< 0.84\,\mu\text{s}$ drops under heavy network loads?
The mitigation fast-path runs inside the network interface card (NIC) driver space using Linux eBPF/XDP. When an incoming frame matches an active threat rule, the kernel returns `XDP_DROP` and recycles the hardware descriptor immediately, avoiding the CPU and memory costs of allocating Linux `sk_buff` socket buffers.

---

### Q4: Can I run third-party security agents (e.g., Splunk, CrowdStrike) alongside `sentinel`?
**Yes.** `blackbox-sentinel` integrates with existing enterprise infrastructure. It exposes industry-standard log forwarders (CEF, LEEF, Syslog RFC 5424, and Kafka) to stream enriched security telemetry to central SIEMs without system conflicts.

