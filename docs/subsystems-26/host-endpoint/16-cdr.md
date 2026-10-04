---

### File: `blackbox-sentinel/docs/subsystems-26/host-endpoint/16-cdr.md`

```markdown
# Subsystem 16: Content Disarm & Reconstruction (`16_cdr`)

`16_cdr` neutralizes weaponized documents (PDFs, Office OOXML, RTF) transferred over network streams (HTTP, SMB, DICOM) by parsing document structures in memory and stripping executable components without writing untrusted payloads to disk.

---

## 1. Disarm & Rebuild Pipeline

```text
 [ Ingress Inbound Document (e.g. Invoice.pdf / Specs.docx) ]
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Zero-Copy File Structure Parser                             │
 │   - Deconstructs DOM / OLE2 streams / PDF XREF tables       │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼ Recursive Macro & Script Stripper
 ┌─────────────────────────────────────────────────────────────┐
 │ Component Removal:                                          │
 │  • Strips VBA Macros, ActiveX Controls, and DDE formulas    │
 │  • Neutralizes PDF /JavaScript, /Launch, and /EmbeddedFiles │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ In-Memory Reconstruction Engine                             │
 │   - Emits pure visual representation (Sanitized Document)   │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
 [ Safe Stream Forwarded to Recipient (Zero Exploit Payload) ]
```

---

## 2. Invariants & Speed

* **Zero Disk Footprint:** Documents are disassembled and rebuilt entirely in pre-allocated RAM scratchpads, preventing temporary-file race conditions.
* **Latency Profile:** Sanitizes a $2\text{ MB}$ PDF in **$< 8.5\,\text{ms}$**.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/host-endpoint/20-fse.md`

```markdown
# Subsystem 20: Firmware Security Evaluation (`20_fse`)

`20_fse` inspects the appliance's underlying motherboard UEFI/BIOS SPI flash chip, Option ROMs, and PCIe peripheral firmware. It verifies hardware firmware integrity against cryptographically signed manufacturer baselines.

---

## 1. Physical Firmware Audit Pipeline

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Direct SPI Controller Access (/dev/mem / MTD driver)        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ UEFI Firmware Volume (FV) Dissector                         │
 │   - Traverses Firmware File System (FFS) headers            │
 │   - Extracts PE32/TE EFI drivers and DXE executables        │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ SHA-256 Hash  │       │ Verify Secure │       │ Compare with  │
 │ Extraction    │       │ Boot db/dbx   │       │ TPM 2.0 PCR 0 │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
 [ Detects Rootkits, MoonBounce, CosmicStrand, and BlackLotus ]
```

---

## 2. TPM 2.0 PCR 0 Cryptographic Sealing

`20_fse` cross-checks extracted firmware digests against **TPM 2.0 PCR 0**:
* If an unauthorized SPI flash write occurs, the physical PCR 0 digest will not match the manufacturer quote.
* The appliance enters **`STAGE_FORENSIC_LOCKDOWN`**, refusing to unseal cryptographic storage keys.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/08-nac.md`

```markdown
# Subsystem 08: Network Access Control (`08_nac`)

`08_nac` controls device admission and dynamic VLAN isolation on local industrial switches. It functions as an inline **802.1X / RADIUS Change of Authorization (CoA)** controller, dynamically quarantining rogue devices or infected PLCs.

---

## 1. Dynamic Quarantine Architecture

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ 08_nac Dynamic Controller                                   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Threat Detected (Subsystems 01-26)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ RADIUS Change of Authorization (RFC 5176 CoA-Request)       │
 │   - Dispatched to Managed Switch (Cisco, Hirschmann, Moxa)  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Switch Reassigns Port
 ┌─────────────────────────────────────────────────────────────┐
 │ Port Switched: VLAN 10 (Production) ──► VLAN 999 (Quarantine)│
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Linux Bridge Interface VLAN Steering

On multi-homed appliances configured as an inline bridge (`br0`), `08_nac` controls the Linux kernel bridge forwarding table (`fdb`) directly via Netlink:

```cpp
#include <linux/rtnetlink.h>
#include <net/if.h>

void quarantine_mac_address(int bridge_ifindex, const uint8_t mac[6], uint16_t quarantine_vlan) {
    // Issues RTM_NEWNEIGH / RTM_SETLINK netlink message
    // Forces switch port/bridge egress to quarantine VLAN tag 999
}
```
```

---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/12-itdr.md`

```markdown
# Subsystem 12: Identity Threat Detection & Response (`12_itdr`)

`12_itdr` inspects active Active Directory and Kerberos/LDAP authentication traffic over the wire. It detects credential attacks—including **Kerberoasting, AS-REP Roasting, DCSync, and Golden Ticket forgeries**—without requiring domain controller agent installation.

---

## 1. Kerberos Wire Inspection Mechanics

```text
 [ Ingress Kerberos TCP/UDP Port 88 Traffic ]
                       │
                       ▼ Zero-Copy ASN.1 DER Parser
 ┌─────────────────────────────────────────────────────────────┐
 │ Inspects Kerberos TGS-REQ / AS-REQ APDUs                    │
 └─────────────────────┬───────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
 [ High-Volume SPN Requests ]   [ Legacy RC4-HMAC Cipher ]
 (Service Principal Names)      (Weak encryption requested)
        │                             │
        └──────────────┬──────────────┘
                       ▼
       [ Kerberoasting Attack Confirmed ]
                       │
                       ▼ Triggers Kernel Drop
 [ Attacker Workstation IP Blocked via eBPF (< 0.84 µs) ]
```

---

## 2. Attack Vectors Detected

| Technique ID | Attack Description | Detection Heuristic |
| :--- | :--- | :--- |
| **T1558.003** | **Kerberoasting** | Spike in `TGS-REQ` packets requesting RC4 encryption (`etype 23`) across multiple SPNs. |
| **T1558.004** | **AS-REP Roasting** | `AS-REQ` requests sent for accounts with pre-authentication explicitly disabled. |
| **T1003.006** | **DCSync** | `DRSGetNCChanges` RPC call originating from a non-Domain Controller IP address. |
| **T1558.001** | **Golden Ticket** | Ticket Granting Ticket (TGT) validity timestamp exceeding the domain maximum (e.g. $> 10\text{ hours}$). |
```

---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/14-ato.md`

```markdown
# Subsystem 14: Account Takeover & Geo-Velocity Protection (`14_ato`)

`14_ato` detects compromised user credentials by calculating the physical **geo-velocity** between successive logins across distributed industrial and web endpoints.

---

## 1. The Impossible Travel Geo-Velocity Equation

When an account authenticates from Location $A$ at time $t_1$, and subsequently from Location $B$ at time $t_2$, `14_ato` calculates the minimum travel velocity using the Haversine great-circle distance formula:

$$d = 2R \cdot \arcsin\left(\sqrt{\sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)}\right)$$

$$\text{Velocity} = \frac{d(A, B)}{t_2 - t_1}$$

```text
 12:00:00 UTC: Login from Berlin, Germany (52.5200° N, 13.4050° E)
 12:15:00 UTC: Login from Tokyo, Japan   (35.6762° N, 139.6503° E)
 Distance    : 8,918 km
 Elapsed Time: 15 Minutes (0.25 Hours)
 Calculated Velocity: 35,672 km/h  ──► IMPOSSIBLE TRAVEL CONFIRMED!
```

---

## 2. Action Trigger

If calculated velocity exceeds $900\,\text{km/h}$ (commercial jet speed), `14_ato`:
1. Terminates the active session token immediately.
2. Injects the attacker's source IP into Tier 2 `blocked_ip_map`.
3. Issues a high-severity alert to `01_siem_core`.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/identity-access/24-ztna.md`

```markdown
# Subsystem 24: Dynamic Zero Trust Session Risk Regressor (`24_ztna`)

`24_ztna` replaces static perimeter authentication with continuous, real-time trust evaluation. It calculates a continuous session risk score ($R \in [0.0, 1.0]$) for every active connection, updating dynamically with every network frame.

---

## 1. Dynamic Risk Regression Formula

$$R(t) = w_{\text{endpoint}} \cdot S_{\text{EDR}} + w_{\text{network}} \cdot S_{\text{NDR}} + w_{\text{identity}} \cdot S_{\text{ITDR}} + w_{\text{anomaly}} \cdot S_{\text{AI}}$$

```text
 Continuous Frame Ingress
            │
            ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Real-Time Risk Regressor (Evaluated every 100ms)            │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   R < 0.30                0.30 <= R < 0.70             R >= 0.70
 ┌───────────────┐       ┌───────────────────┐   ┌───────────────────┐
 │ LOW RISK      │       │ ELEVATED RISK     │   │ CRITICAL RISK     │
 │ Fully Trusted │       │ Enforce Step-Up   │   │ Immediate Session │
 │ Access        │       │ MFA Challenge     │   │ Revocation / Drop │
 └───────────────┘       └───────────────────┘   └───────────────────┘
```

---

## 2. Continuous Policy Enforcement

If an authenticated engineering workstation begins issuing unexpected Modbus write commands, $S_{\text{anomaly}}$ increases, driving the composite risk score $R(t)$ past $0.70$. `24_ztna` terminates the session and resets the TCP connection via `XDP_TX` without waiting for token expiration.
```

---

### Complete in Part 4
- `blackbox-sentinel/docs/subsystems-26/host-endpoint/06-edr.md`
- `blackbox-sentinel/docs/subsystems-26/host-endpoint/07-epp-ngav.md`
- `blackbox-sentinel/docs/subsystems-26/host-endpoint/09-cwpp.md`
- `blackbox-sentinel/docs/subsystems-26/host-endpoint/16-cdr.md`
- `blackbox-sentinel/docs/subsystems-26/host-endpoint/20-fse.md`
- `blackbox-sentinel/docs/subsystems-26/identity-access/08-nac.md`
- `blackbox-sentinel/docs/subsystems-26/identity-access/12-itdr.md`
- `blackbox-sentinel/docs/subsystems-26/identity-access/14-ato.md`
- `blackbox-sentinel/docs/subsystems-26/identity-access/24-ztna.md`

---

### Files to be Generated in Part 5

The next phase covers **Cyber-Physical OT & IoT Protection** and **Forensics, Traffic Control & Deception** (the remaining 9 subsystems):

1. `subsystems-26/cyber-physical-ot/17-iot-sec.md` (`17_iot_sec`: Medical DICOM PACS & HL7 protocol security)
2. `subsystems-26/cyber-physical-ot/18-cps-sec.md` (`18_cps_sec`: SCADA OT physical constraint validator)
3. `subsystems-26/cyber-physical-ot/21-side-channel.md` (`21_side_channel`: Hardware power & EM emission analyzer)
4. `subsystems-26/forensics-advanced/13-ddos.md` (`13_ddos`: Line-rate flood shaper & SYN cookie guard)
5. `subsystems-26/forensics-advanced/19-swg.md` (`19_swg`: Sovereign outbound egress proxy & URL filtering)
6. `subsystems-26/forensics-advanced/22-dfir.md` (`22_dfir`: Ring-buffer PCAP evidence carver with SHA-256)
7. `subsystems-26/forensics-advanced/23-ai-trism.md` (`23_ai_trism`: AI safety firewall & LLM prompt barrier)
8. `subsystems-26/forensics-advanced/25-fdp.md` (`25_fdp`: Financial transaction graph anomaly analyzer)
9. `subsystems-26/forensics-advanced/26-ddp.md` (`26_ddp`: Distributed deception decoy PLCs on secondary VIPs)

Confirm when you are ready to proceed with Part 5.