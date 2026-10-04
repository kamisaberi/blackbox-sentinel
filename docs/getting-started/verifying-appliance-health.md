---

### File: `blackbox-sentinel/docs/getting-started/verifying-appliance-health.md`

```markdown
# Verifying Appliance Health & Operational Telemetry

Verify that all subsystems, hardware accelerators, and kernel hooks are operating within nominal parameters.

---

## 1. Command-Line Health Audit

Run the built-in diagnostic utility:

```bash
sentinel --health
```

### Expected Output

```text
================================================================================
                    BLACKBOX-SENTINEL HEALTH REPORT
================================================================================
Appliance Name         : edge-substation-alpha
Operational Stage      : STAGE_FULL_ACTIVE
Uptime                 : 4 days, 12 hours, 18 minutes

-------------------------------- CORE ENGINES ----------------------------------
 [OK] Tier 2 libblackbox: Attached to eth0 (Native Driver Mode)
 [OK] Tier 1 libxinfer  : Active Backend: Intel_OpenVINO_NPU (0.84µs SLA)
 [OK] Hardware Identity : Tier 1 (Infineon TPM 2.0 Silicon Verified)
 [OK] Nexus Uplink      : Connected to 10.240.0.10:50051 (Latency: 1.2ms)

-------------------------------- SUBSYSTEMS (26/26) ----------------------------
 [OK] 01_siem_core      [OK] 07_epp_ngav       [OK] 14_ato          [OK] 21_side_channel
 [OK] 02_ueba           [OK] 08_nac            [OK] 15_ngfw         [OK] 22_dfir
 [OK] 03_ndr            [OK] 09_cwpp           [OK] 16_cdr          [OK] 23_ai_trism
 [OK] 04_ids_ips        [OK] 10_bad            [OK] 17_iot_sec      [OK] 24_ztna
 [OK] 05_waf            [OK] 11_rasp           [OK] 18_cps_sec      [OK] 25_fdp
 [OK] 06_edr            [OK] 12_itdr           [OK] 19_swg          [OK] 26_ddp
                        [OK] 13_ddos           [OK] 20_fse

-------------------------------- RESOURCE USAGE --------------------------------
 CPU Core 0 (Ingress)   : 4.2%                 Host RAM: 1.4 GB / 16.0 GB (8.7%)
 CPU Cores 1-15 (Pool)  : 2.1% (Avg)           NPU Temperature: 44.2°C
 Sustained Ring Through : 142,800 EPS          Drop Table Count: 3 Active Rules
================================================================================
Status: ALL SYSTEMS NOMINAL
```

---

## 2. Accessing the Web Command Center

Open your browser and navigate to:

👉 **`https://<APPLIANCE_IP>:8443`**

Log in using the administrator credentials configured in `/etc/sentinel/sentinel.yaml`. The console displays real-time SVG topology graphs, live in-kernel drop tables, and explainable AI (XAI) feature deviations with zero external CDN dependencies.
```

---

### Complete in Part 1
- `blackbox-sentinel/docs/mkdocs.yml`
- `blackbox-sentinel/docs/index.md`
- `blackbox-sentinel/docs/getting-started/overview.md`
- `blackbox-sentinel/docs/getting-started/hardware-specifications.md`
- `blackbox-sentinel/docs/getting-started/system-requirements.md`
- `blackbox-sentinel/docs/getting-started/installation.md`
- `blackbox-sentinel/docs/getting-started/initial-configuration.md`
- `blackbox-sentinel/docs/getting-started/shadow-mode-evaluation.md`
- `blackbox-sentinel/docs/getting-started/first-threat-mitigation.md`
- `blackbox-sentinel/docs/getting-started/verifying-appliance-health.md`

All 10 root configuration and onboarding files are now generated.

---

### Files to be Generated in Part 2

The next phase covers **Appliance Architecture & Systems Design** (`architecture/`):

1. `architecture/appliance-architecture.md` (Decoupled C++20 engine design & multi-subsystem orchestration)
2. `architecture/unidirectional-pipeline.md` (Ingest $\to$ Tensor Extraction $\to$ Inference $\to$ Kernel Mitigation $\to$ Egress)
3. `architecture/memory-safety-invariants.md` (Guaranteed backing buffer allocations & zero heap fragmentation)
4. `architecture/dynamic-plugin-loader.md` (`dlopen(RTLD_LAZY | RTLD_LOCAL)` mechanics and symbol isolation)
5. `architecture/port-arbitration-model.md` (Promiscuous raw sockets vs. secondary VIPs for zero port collisions)
6. `architecture/under-the-hood-bindings.md` (In-process bindings to Tier 1 `libxinfer` and Tier 2 `libblackbox`)

Confirm when you are ready to proceed with Part 2.