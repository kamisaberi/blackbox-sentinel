# Master Startup Roadmap: Blackbox Sentinel™
## Commercial Launch & Execution Plan (Days 1 to 180)

---

### Executive Roadmap Overview

```text
[ PHASE 0 ] ------------> [ PHASE 1 ] ------------> [ PHASE 2 ] ------------> [ PHASE 3 ] ------------> [ PHASE 4 ] ------------> [ PHASE 5 ]
Days 1–7                  Days 7–30                 Days 30–60                Days 60–75                Days 75–120               Days 120–180
MVP Code Freeze           Bare-Metal & eBPF         AI Model Sourcing         Corporate & Legal         Design Partner            Commercial Launch
& Architecture Audit      Kernel Hardening          & ONNX Export             Formation                 Field Pilots              & Seed Fundraising
```

---

### Phase 0: MVP Code Freeze & Architecture Audit (Days 1 – 7)

**Primary Objective:** Lock the initial software prototype, tag the version in git, and verify the clean separation of your 3-layer architecture before moving to physical hardware.

#### Technical Tasks
- **Git Tagging:** Create tag `v0.1.0-mvp` across all three repositories (`xinfer-essential`, `blackbox-essential`, `blackbox-sentinel`).
- **Shared Library Verification:** Confirm `libxinfer.so` and `libblackbox.so` install cleanly into `/usr/local/lib` and that headers land in `/usr/local/include/`.
- **Simulation Archive:** Preserve your Docker simulation testbed (`docker-compose.massive.yml`) and attack controller (`attack_console.py`) for automated regression testing during future updates.

#### Deliverable
- A clean, compiling C++20 baseline across all 3 layers running on your Ubuntu VM.

---

### Phase 1: Bare-Metal Hardware Hardening & Wire-Speed Optimization (Days 7 – 30)

**Primary Objective:** Transition from VMware virtualized network interfaces to bare-metal Linux hardware with physical NICs, native eBPF/XDP kernel drivers, and TPM 2.0 hardware security.

#### Technical Tasks
- **Bare-Metal Testbed Setup:** Install Ubuntu 22.04 LTS on a physical bare-metal host (e.g., an x86 server with an Intel/NVIDIA NIC, or an NVIDIA Jetson Orin / Rockchip RK3588 board).
- **Native eBPF/XDP Kernel Bytecode (`src/mitigation/xdp_drop.c`):**
  - Replace the `iptables` CLI fallback in `ebpf_blocker.cpp` with native BPF C kernel code using `libbpf`.
  - Write a BPF hash map (`bpf_map_update_elem`) so `blackbox` updates blocked IP addresses directly in kernel memory without user-space overhead.
- **AF_XDP Wire-Speed Ingestion (`src/ingest/network_ingest.cpp`):**
  - Implement Linux `AF_XDP` (XDP Sockets) zero-copy ring buffers to process network packets at 10Gbps line rate directly into `blackbox` RAM.
- **Physical TPM 2.0 Integration (`src/hardware/tpm_license.cpp`):**
  - Replace dummy hardware checks with real TPM 2.0 C API calls (`libtss2-esys` / `/dev/tpmrm0`) to lock `sentinel` execution to the physical motherboard UUID and TPM key.

#### Deliverable
- Sub-millisecond wire-speed packet ingestion and kernel IP dropping verified on physical hardware.

---

### Phase 2: AI Model Sourcing, Fine-Tuning & ONNX Conversion (Days 30 – 60)

**Primary Objective:** Replace dummy/vision ONNX models with real, fine-tuned security models trained specifically for network intrusion detection, log analysis, and physical perimeter security.

#### Model Engineering Tasks

| Model Domain | Dataset / Source | Architecture | Export Command / Output File |
| :--- | :--- | :--- | :--- |
| **Network Anomaly Detection** | CIC-IDS2017 / UNSW-NB15 | IsolationForest / Deep Autoencoder | Convert via `skl2onnx` $\rightarrow$ `models/network_threat.onnx` |
| **Physical Perimeter Intrusion** | COCO / Custom CCTV | YOLOv11n (Ultralytics) | `yolo export model=yolov11n.pt format=onnx` $\rightarrow$ `models/vision_yolo.onnx` |
| **Log Anomaly NLP** | Syslog / Linux Auditd Logs | DistilBERT / Qwen2.5-0.5B | Export via Hugging Face Optimum $\rightarrow$ `models/log_nlp.onnx` |

#### Integration Tasks
- Host your trained `.onnx` model files on official GitHub Releases (or an S3 bucket).
- Configure `configs/sentinel_config.json` so `xinfer::ModelHub` automatically fetches and caches these ONNX models on first boot.

#### Deliverable
- A fully populated `models/` directory containing fine-tuned, verified ONNX models running on `libxinfer.so`.

---

### Phase 3: Legal, Corporate Formation & Security Compliance (Days 60 – 75)

**Primary Objective:** Establish the legal corporate entity, assign all intellectual property (IP) to the company, and generate compliance marketing collateral.

#### Business & Legal Tasks
- **Corporate Entity Formation:** Form a Delaware C-Corporation (or regional equivalent, e.g., GmbH) to enable institutional VC investment.
- **IP Assignment Agreements:** Execute formal Intellectual Property Assignment agreements transferring all code, trademarks, and documentation for `xinfer`, `blackbox`, and `blackbox-sentinel` from the founder(s) to the corporate entity.
- **Commercial Licensing Terms:** Finalize the commercial End User License Agreement (EULA) and B2B OEM Licensing Agreement for `libblackbox.so` and `libxinfer.so`.
- **Compliance Export Templates:** Verify that `report_generator.cpp` produces audit-ready compliance reports matching **CMMC Level 2, ISO 27001, and NIST 800-53** formats.

#### Deliverable
- Legally incorporated company with 100% owned IP, commercial EULAs, and compliance report templates.

---

### Phase 4: Design Partner Pilot Program & Field Testing (Days 75 – 120)

**Primary Objective:** Deploy turnkey Blackbox Sentinel hardware appliances into 3 real-world beta customer environments to gather case studies, benchmark numbers, and testimonials.

#### Target Beta Profiles
1. **Pilot 1 (Smart Factory / Industrial Automation):** Deploy at a local automated manufacturing plant or SCADA facility.
2. **Pilot 2 (Regional Data Center / MSSP):** Deploy at a local managed security service provider or high-density server facility.
3. **Pilot 3 (Maritime / Logistics Operator):** Deploy at a port, cargo facility, or maritime logistics node.

#### Deployment Timeline per Pilot (4 Weeks Total)

```text
Week 1: Installation & Monitor Mode
  - Deploy 1U server or Jetson box in "Monitor Mode" (passive logging, zero active blocking).
  - Establish baseline network traffic and log patterns.

Week 2: Anomaly Threshold Tuning
  - Adjust configs/default_rules.json based on customer network traffic.
  - Tune AI model confidence thresholds to achieve zero false positives.

Week 3–4: Active Enforcement Mode
  - Enable eBPF kernel active blocking and physical alarm relays.
  - Test live simulated attacks with the customer's IT/OT team.

Week 4: Executive Review & Case Study
  - Generate a CMMC/ISO27001 PDF report for the CISO/Factory Director.
  - Secure a written customer testimonial and permission to use their logo.
```

#### Deliverable
- 3 completed pilot deployments, 3 written case studies, and verified real-world latency metrics.

---

### Phase 5: Commercial Launch, Sales & Fundraising (Days 120 – 180)

**Primary Objective:** Launch the commercial product, execute cold outreach to enterprise security buyers, present at defense/cybersecurity trade shows, and raise a Seed funding round.

#### Marketing Assets & Collateral
1. **The 90-Second "Magic Demo" Video:**
   - Recorded on physical hardware showing an attack launched from a simulated machine, intercepted by `blackbox` in eBPF in microseconds, and rendered live on the Web Command Center UI.
2. **Commercial Landing Page Website:**
   - Featuring the demo video, product one-pagers, case studies from Phase 4, and a "Request a 30-Day Pilot" button.
3. **Product One-Pager Datasheet (PDF):**
   - Highlighting hardware specifications, eBPF drop speeds, air-gapped security, and supported compliance standards.

#### Sales & Go-To-Market Execution
- **Direct Enterprise Sales:** Target CISOs and Industrial Security Directors with a 3-email sequence offering a live 15-minute demonstration of kernel-level eBPF packet drops.
- **Channel Partnerships:** Sign Value-Added Reseller (VAR) agreements with industrial automation distributors and defense prime integrators.
- **Seed Fundraising ($500k – $1.5M):**
  - Pitch deep-tech and cybersecurity VCs using your working hardware demo, initial revenue/pilots, and the 3-layer software stack architecture.

#### Target Sales Pricing

```text
Turnkey Hardware Appliance Sale : $25,000 (One-Time Upfront)
Annual Software Subscription    : $10,000 / year / node (Recurring ARR)
Commercial Add-On Plugin Packs  : $5,000 – $15,000 / year (Optional)
```

---

### Master Timeline & Milestone Summary

| Timeframe | Phase | Key Milestone |
| :--- | :--- | :--- |
| **Days 1–7** | **Phase 0** | Code freeze, tag `v0.1.0-mvp`, verify 3-layer shared library builds. |
| **Days 7–30** | **Phase 1** | Deploy on bare-metal hardware, implement native BPF C maps and TPM 2.0. |
| **Days 30–60** | **Phase 2** | Train & export fine-tuned ONNX models for network, vision, and log threat detection. |
| **Days 60–75** | **Phase 3** | Form Delaware C-Corp, assign IP, finalize commercial EULAs. |
| **Days 75–120** | **Phase 4** | Run 3 Design Partner beta pilots; collect case studies and testimonials. |
| **Days 120–180** | **Phase 5** | Launch website, publish 90s demo video, sign first 5 paid contracts, raise Seed round. |

---

### Critical Failure Points and How to Avoid Them

1. **Avoid Scope Creep:** Do not add new features during Phase 4 (Pilots). Keep the software stable.
2. **Avoid False Positives:** During Week 2 of every pilot, ensure `anomaly_threshold` is properly tuned so legitimate customer traffic is never accidentally dropped by eBPF.
3. **Protect the Engine:** Keep `libxinfer.so` and `libblackbox.so` strictly separated from upper-level UI code to preserve maximum execution speed and maintainability.