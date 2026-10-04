---

### File: `blackbox-sentinel/docs/subsystems-26/web-application/10-bad.md`

```markdown
# Subsystem 10: Bot & Automated Abuse Defense (`10_bad`)

`10_bad` detects automated scrapers, credential-stuffing bots, and DDoS flooding scripts by analyzing the **kinematic curves** of client interactions and the statistical periodicity of incoming HTTP requests.

---

## 1. Kinematic Curve Analysis

Human interactions (mouse movements, touch swipes) exhibit continuous acceleration, deceleration, and natural jitter governed by physical biomechanics. Bots generate linear vectors, programmatic Bezier curves, or instantaneous point jumps:

```text
 HUMAN MOUSE VELOCITY PROFILE:
 Velocity
   ▲         .-.
   │        /   \     (Continuous acceleration/deceleration curves)
   │   .---'     `--.
   └───┴──────────────┴────► Time

 AUTOMATED BOT MOVEMENT PROFILE:
 Velocity
   ▲   ┌─────────┐
   │   │         │    (Instantaneous acceleration; static intervals)
   └───┴─────────┴─────────► Time
```

---

## 2. Request Periodicity FFT

`10_bad` computes a Fast Fourier Transform (FFT) over the inter-arrival times of incoming requests per IP. Automated loops display sharp spectral peaks at fixed intervals (e.g., exactly every $100\,\text{ms}$), triggering automated mitigation.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/web-application/11-rasp.md`

```markdown
# Subsystem 11: Runtime Application Self-Protection (`11_rasp`)

`11_rasp` monitors the runtime memory integrity of the host daemon and co-located mission applications. It inspects process memory maps, detecting Procedure Linkage Table (PLT) hijacking, Global Offset Table (GOT) overwrites, and Return-Oriented Programming (ROP) execution chains.

---

## 1. In-Memory Hook Detection

`11_rasp` periodically audits the process memory spaces defined in `/proc/self/maps`:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Auditing Process Address Space                              │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ Check PLT/GOT │       │ Verify Shared │       │ Validate Call │
 │ Relocations   │       │ Library Hashes│       │ Stack Frames  │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Tampering Detected
                                 ▼
           [ Terminate Corrupted Context & Alert SIEM ]
```

---

## 2. Anti-Debugging & Anti-Tamper Invariants

* **`ptrace` Scope:** Automatically invokes `prctl(PR_SET_DUMPABLE, 0)` on initialization, preventing unprivileged processes from attaching debuggers or reading process memory.
* **Stack Canary Validation:** Re-verifies compiler-injected stack canaries across all high-frequency worker loops.
```

---

### Complete in Part 3
- `blackbox-sentinel/docs/subsystems-26/index.md`
- `blackbox-sentinel/docs/subsystems-26/enterprise-it/01-siem-core.md`
- `blackbox-sentinel/docs/subsystems-26/enterprise-it/02-ueba.md`
- `blackbox-sentinel/docs/subsystems-26/enterprise-it/03-ndr.md`
- `blackbox-sentinel/docs/subsystems-26/enterprise-it/04-ids-ips.md`
- `blackbox-sentinel/docs/subsystems-26/enterprise-it/15-ngfw.md`
- `blackbox-sentinel/docs/subsystems-26/web-application/05-waf.md`
- `blackbox-sentinel/docs/subsystems-26/web-application/10-bad.md`
- `blackbox-sentinel/docs/subsystems-26/web-application/11-rasp.md`

---

### Files to be Generated in Part 4

The next phase covers **Host, Workload & Binary Security** and **Identity & Access Governance** (9 subsystems):

1. `subsystems-26/host-endpoint/06-edr.md` (`06_edr`: Endpoint process tree analyzer & memory injection hunter)
2. `subsystems-26/host-endpoint/07-epp-ngav.md` (`07_epp_ngav`: Real-time file Shannon entropy calculator & IOPS blocker)
3. `subsystems-26/host-endpoint/09-cwpp.md` (`09_cwpp`: Container eBPF syscall breakout guard at `sys_enter`)
4. `subsystems-26/host-endpoint/16-cdr.md` (`16_cdr`: Content Disarm & Reconstruction macro stripper)
5. `subsystems-26/host-endpoint/20-fse.md` (`20_fse`: Firmware Security Evaluation & UEFI/BIOS dissector)
6. `subsystems-26/identity-access/08-nac.md` (`08_nac`: 802.1X dynamic VLAN quarantine controller)
7. `subsystems-26/identity-access/12-itdr.md` (`12_itdr`: Identity threat detection, Kerberoasting & AD abuse)
8. `subsystems-26/identity-access/14-ato.md` (`14_ato`: Account takeover & impossible travel geo-velocity check)
9. `subsystems-26/identity-access/24-ztna.md` (`24_ztna`: Dynamic Zero Trust session risk regressor)

Confirm when you are ready to proceed with Part 4.