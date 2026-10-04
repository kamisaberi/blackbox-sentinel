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