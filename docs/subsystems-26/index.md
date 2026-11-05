# The 26 Native C++20 Subsystems

`blackbox-sentinel` integrates 26 decoupled security modules compiled directly into `sentinel`. Each subsystem operates within an isolated memory envelope.

## Section Navigation

### Enterprise IT & Detection
- [01 SIEM Core](./enterprise-it/01-siem-core.md): In-memory log correlation and indexing engine ($> 1\text{M EPS}$).
- [02 UEBA](./enterprise-it/02-ueba.md): User & Entity Behavior Analytics using a 100k-entity state matrix.
- [03 NDR](./enterprise-it/03-ndr.md): Network Detection & Response with TLS JA3/JA4 fingerprinting.
- [04 IDS/IPS](./enterprise-it/04-ids-ips.md): Intrusion Detection using SIMD Aho-Corasick pattern matching.
- [15 NGFW](./enterprise-it/15-ngfw.md): Next-Generation Firewall with L7 protocol state machine.

### Web & Application
- [05 WAF](./web-application/05-waf.md): Web Application Firewall protecting against OWASP Top 10 vulnerabilities.
- [10 BAD](./web-application/10-bad.md): Bot & Automated Abuse Defense using kinematic curve analysis.
- [11 RASP](./web-application/11-rasp.md): Runtime Application Self-Protection detecting PLT/GOT memory hooks.

### Host, Workload & Binary
- [06 EDR](./host-endpoint/06-edr.md): Endpoint Detection & Response tracking Linux Netlink process trees.
- [07 EPP/NGAV](./host-endpoint/07-epp-ngav.md): Next-Gen Antivirus using SIMD Shannon Entropy calculation.
- [09 CWPP](./host-endpoint/09-cwpp.md): Cloud Workload Protection inspecting eBPF container syscalls.
- [16 CDR](./host-endpoint/16-cdr.md): Content Disarm & Reconstruction sanitizing weaponized documents.
- [20 FSE](./host-endpoint/20-fse.md): Firmware Security Evaluation auditing UEFI/BIOS SPI flash volumes.

### Identity & Access
- [08 NAC](./identity-access/08-nac.md): Network Access Control executing 802.1X / RADIUS VLAN isolation.
- [12 ITDR](./identity-access/12-itdr.md): Identity Threat Detection inspecting Kerberos & DCSync attacks.
- [14 ATO](./identity-access/14-ato.md): Account Takeover Protection detecting impossible travel geo-velocity.
- [24 ZTNA](./identity-access/24-ztna.md): Zero Trust Network Access calculating real-time session risk scores.

### Cyber-Physical OT
- [17 IoT Security](./cyber-physical-ot/17-iot-sec.md): Medical IoT & DICOM PACS radiology protocol protection.
- [18 CPS Security](./cyber-physical-ot/18-cps-sec.md): SCADA Physical Constraint Validator for Modbus/S7/DNP3.
- [21 Side-Channel Defense](./cyber-physical-ot/21-side-channel.md): Power & EM Waveform Spectral Anomaly Analyzer.

### Forensics, Control & Deception
- [13 DDoS Guard](./forensics-advanced/13-ddos.md): Line-rate flood shaper emitting in-kernel eBPF SYN cookies.
- [19 SWG](./forensics-advanced/19-swg.md): Sovereign Web Gateway enforcing $0.00 cloud egress policies.
- [22 DFIR](./forensics-advanced/22-dfir.md): Circular PCAP Evidence Carver with TPM 2.0 digital signatures.
- [23 AI-TRiSM](./forensics-advanced/23-ai-trism.md): AI Safety Firewall blocking prompt injection & jailbreak vectors.
- [25 FDP](./forensics-advanced/25-fdp.md): Financial Transaction Graph Anomaly Analyzer (ISO 20022 / FIX).
- [26 DDP](./forensics-advanced/26-ddp.md): Distributed Deception Platform deploying synthetic PLCs on VIPs.
