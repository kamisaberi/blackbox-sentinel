---

### File: `blackbox-sentinel/docs/getting-started/overview.md`

```markdown
# Autonomous Edge Active Defense & SIEM Appliance Introduction

Traditional Security Information and Event Management (SIEM) and Extended Detection and Response (XDR) architectures rely on forwarding raw logs and PCAP streams to centralized cloud data lakes. In critical infrastructure—such as power substations, semiconductor manufacturing plants, healthcare enclaves, and autonomous naval systems—this paradigm introduces operational failure modes:

* **Latency Latency:** Alerting pipelines take $15 - 60\text{ seconds}$ to ingest, parse, query, and flag incidents, during which an attacker can execute PLC coil overrides or exfiltrate databases.
* **Egress Costs & Bandwidth Saturation:** Pushing terabytes of continuous telemetry over cellular or satellite datalinks incurs thousands of dollars in cloud egress fees.
* **Data Sovereignty Violations:** Regulatory directives (EU NIS 2, CMMC 2.0, HIPAA) strictly forbid routing unencrypted operational technology (OT) payloads through third-party servers.

---

## 1. The Edge Appliance Paradigm

`blackbox-sentinel` is deployed as an on-premises physical appliance (or localized virtual machine) positioned directly on the operational network boundary:

```text
 [ INDUSTRIAL OT / HEALTHCARE ENCLAVE ]
                  │
                  ▼ Ingress Packets (SPAN / TAP / Inline)
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Edge Appliance                            │
 │  - In-Memory Protocol Dissection (< 5 µs)                   │
 │  - Local Microsecond AI Scoring (OpenVINO / TensorRT NPU)   │
 │  - Direct In-Kernel eBPF Drops (< 0.84 µs)                  │
 │  - Embedded On-Appliance SIEM Storage                       │
 └────────────────┬────────────────────────────┬───────────────┘
                  │                            │
                  ▼ Clean Traffic              ▼ Filtered Telemetry Only
          [ Protected PLCs ]           [ Nexus Central Hub ]
```

---

## 2. The 5 Core Operational Stages

The daemon transitions through five execution stages to ensure risk-free onboarding:

1. **`STAGE_SHADOW_MODE` (Passive Audit):** Operates on a network TAP or SPAN port. AI models and protocol parsers score live traffic without dropping any packets.
2. **`STAGE_CANARY_ACTIVE` (Targeted Enforcement):** Enforces in-kernel drops only on high-confidence ($> 0.95$) attack signatures or critical SCADA register tampering.
3. **`STAGE_FULL_ACTIVE` (Autonomous Edge Mitigation):** Inline autonomous protection. Malicious flows are purged in driver memory in $< 0.84\,\mu\text{s}$.
4. **`STAGE_DECEPTION_ACTIVE` (Active Honeypots):** Emulates vulnerable virtual PLC decoys on secondary VIPs to mislead reconnaissance scans.
5. **`STAGE_FORENSIC_LOCKDOWN` (Emergency Air-Gap):** Automatically severs non-critical interfaces while preserving tamper-evident local PCAP evidence.
```

---

### File: `blackbox-sentinel/docs/getting-started/hardware-specifications.md`

```markdown
# Hardware Sizing & Appliance Specifications

`blackbox-sentinel` is available across three reference deployment form factors:

---

## 1. Model S-1000: Industrial DIN-Rail Edge Gateway

Designed for electrical substations, oil/gas wellheads, water treatment facilities, and rail transport cabinets.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Model S-1000 Industrial DIN-Rail (Fanless Aluminum Chassis) │
 │  - Dimensions: 150mm x 100mm x 55mm                         │
 │  - Operating Temperature: -40°C to +75°C (Fanless)          │
 │  - Power Supply: Dual Redundant 12V-36V DC Terminal Block   │
 └─────────────────────────────────────────────────────────────┘
```

* **Processor:** Intel Core Ultra 7 165H (16 Cores, integrated NPU) or Rockchip RK3588 (8 Cores, 6 TOPS NPU).
* **Memory:** 16 GB DDR5 / LPDDR5 ECC RAM (Non-swappable).
* **Storage:** 128 GB Industrial Wide-Temp NVMe SSD (Encrypted with TPM 2.0).
* **Network Interfaces:** 4x 1GbE RJ45 (Intel i226-IT), bypass relay supported.
* **Hardware Identity:** Discrete Infineon OPTIGA TPM 2.0 (`/dev/tpmrm0`).
* **Throughput Capacity:** Up to $250{,}000\text{ EPS}$ sustained; $< 0.84\,\mu\text{s}$ mitigation.

---

## 2. Model S-5000: Enterprise 1U Rackmount Appliance

Designed for enterprise datacenters, hospital core switches, and municipal utility operations centers.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Model S-5000 Enterprise 1U Rackmount Server                 │
 │  - Dual Redundant 750W Titanium Power Supplies              │
 │  - Hot-swappable enterprise cooling fan array               │
 └─────────────────────────────────────────────────────────────┘
```

* **Processor:** Dual Intel Xeon Platinum 8480+ (112 Cores total) or AMD EPYC 9654.
* **AI Acceleration:** Dedicated NVIDIA RTX A4000 (16 GB VRAM) or Intel Data Center GPU Flex 140.
* **Memory:** 128 GB DDR5-4800 Registered ECC RAM.
* **Storage:** 2x 1.92 TB Enterprise U.2 NVMe SSDs in RAID 1.
* **Network Interfaces:** 4x 10GbE/25GbE SFP28 (Intel E810-XXVDA2) with native AF_XDP driver support.
* **Hardware Identity:** Discrete STMicroelectronics ST33 TPM 2.0.
* **Throughput Capacity:** Up to $1{,}250{,}000\text{ EPS}$ sustained; $14.88\text{ Mpps}$ line-rate packet drops.

---

## 3. Model V-Edge: Virtualized Hypervisor Edge Appliance

Designed for private cloud datacenters, virtual SCADA testbeds, and edge VMware deployments.

* **Supported Hypervisors:** VMware vSphere ESXi 8.0+, KVM/QEMU, Proxmox VE 8.x.
* **Minimum Virtual Sizing:**
  * 4 Virtual CPUs (vCPU) with CPU Host Passthrough enabled.
  * 8 GB Assigned RAM (100% Reserved, zero memory ballooning).
  * 64 GB Virtual Disk on fast NVMe storage.
  * Virtual Network Adapter: `vmxnet3` (VMware) or `virtio-net` (KVM).
  * Hardware Attestation: Virtual TPM (vTPM) 2.0 enabled in VM settings.
```

---

### File: `blackbox-sentinel/docs/getting-started/system-requirements.md`

```markdown
# System Requirements & Prerequisites

Review the toolchain, kernel dependencies, and hardware privileges before running `blackbox-sentinel`.

---

## 1. Operating System Baseline

`blackbox-sentinel` is compiled and verified against modern Linux server baselines:

* **Recommended OS:** Ubuntu 24.04 LTS (Noble Numbat) or Ubuntu 26.04 (Devel).
* **Linux Kernel:** Kernel version **>= 6.8** (Minimum: 5.15 LTS with backported BTF).
* **C Library:** GNU C Library (`glibc`) version **>= 2.35** (Verified up to `glibc 2.43`).

---

## 2. Required Linux Kernel Subsystems

Ensure the following kernel configuration flags are set to `=y` in your running kernel:

```bash
# Verify kernel capabilities
cat /boot/config-$(uname -r) | grep -E 'CONFIG_BPF|CONFIG_XDP|CONFIG_NET_CLS_ACT'
```

* `CONFIG_BPF=y` & `CONFIG_BPF_SYSCALL=y`: Core eBPF engine.
* `CONFIG_BPF_JIT=y`: Native instruction JIT compiler.
* `CONFIG_DEBUG_INFO_BTF=y`: BPF Type Format for CO-RE portability.
* `CONFIG_XDP_SOCKETS=y`: High-speed AF_XDP packet transport.

---

## 3. Network Hardware Privileges (`Capabilities`)

When running `sentinel` as a dedicated non-root service user, grant the following POSIX Linux capabilities:

```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_bpf,cap_sys_resource=+ep' /usr/local/bin/sentinel
```

* **`CAP_NET_ADMIN`:** Required to attach eBPF programs to network device hooks.
* **`CAP_NET_RAW`:** Required to open promiscuous raw sockets and inspect raw frames.
* **`CAP_BPF`:** Required to load BPF bytecode and allocate maps.
* **`CAP_SYS_RESOURCE`:** Required to pin memory pages (`mlock`) without `ulimit -l` bounds.
```

---

### File: `blackbox-sentinel/docs/getting-started/installation.md`

```markdown
# Installation & Deployment Guide

This guide covers deploying `blackbox-sentinel` on bare-metal systems, configuring systemd daemons, or importing pre-built virtual appliance images (OVA / QCOW2).

---

## 1. Bare-Metal Package Installation (Ubuntu / Debian)

Aryorithm maintains signed `.deb` packages for enterprise subscribers:

```bash
# 1. Add Aryorithm GPG Signing Key
sudo curl -fsSL https://packages.aryorithm.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/aryorithm.gpg

# 2. Add Package Repository
echo "deb [signed-by=/usr/share/keyrings/aryorithm.gpg] https://packages.aryorithm.com/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/aryorithm.list

# 3. Install Sentinel Daemon and Dependencies
sudo apt-get update && sudo apt-get install -y blackbox-sentinel
```

---

## 2. Manual Source Compilation & Installation

If building from the unified `sentinel-stack` meta-installer:

```bash
cd /opt/sentinel-stack
sudo ./install.sh
```

Alternatively, build `blackbox-sentinel` individually:

```bash
cd blackbox-sentinel
mkdir build && cd build
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja -j$(nproc)
sudo ninja install
```

---

## 3. Systemd Service Deployment

Enable and start the daemon as an automated background service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinel
sudo systemctl start sentinel
```

Check real-time execution status:

```bash
sudo systemctl status sentinel
```

---

## 4. Virtual Appliance Import (OVA / QCOW2)

For fast deployment in virtualized environments:

### VMware vSphere / ESXi (OVA Import)
```bash
# Deploy using ovftool
ovftool --acceptAllEulas \
    --datastore="Datastore1" \
    --name="Blackbox-Sentinel-Edge-01" \
    --net:"VM Network"="Protected_OT_VLAN" \
    blackbox-sentinel-v-edge.ova \
    vi://root@esxi-host-01.internal/
```

### KVM / Proxmox (QCOW2 Import)
```bash
# Create VM and import disk image
qm create 200 --name sentinel-edge --memory 8192 --cores 4 --net0 virtio,bridge=vmbr0
qm importdisk 200 blackbox-sentinel-v-edge.qcow2 local-zfs
qm set 200 --scsihw virtio-scsi-pci --scsi0 local-zfs:vm-200-disk-0
qm set 200 --boot c --bootdisk scsi0
```
```

---

### File: `blackbox-sentinel/docs/getting-started/initial-configuration.md`

```markdown
# Initial Configuration (`/etc/sentinel/sentinel.yaml`)

All operational settings for `blackbox-sentinel` are declared in `/etc/sentinel/sentinel.yaml`.

---

## 1. Minimal Production Configuration

```yaml
version: "1.0.0"

appliance:
  node_name: "edge-substation-alpha"
  deployment_stage: "STAGE_SHADOW_MODE" # Options: STAGE_SHADOW_MODE, STAGE_FULL_ACTIVE
  log_level: "INFO"

network:
  primary_interface: "eth0"
  promiscuous_mode: true
  xdp_attach_mode: "DRIVER" # DRIVER (Native) or SKB (Generic)
  bpf_filter_path: "/usr/local/lib/bpf/xdp_filter.o"

ai_runtime:
  model_path: "/opt/sentinel/models/network_threat_v2.onnx"
  target_backend: "AUTO" # Resolves OpenVINO, TensorRT, or CPU
  enable_zero_copy: true

web_console:
  enabled: true
  bind_address: "0.0.0.0"
  port: 8443
  ssl_certificate: "/etc/sentinel/certs/server.crt"
  ssl_private_key: "/etc/sentinel/certs/server.key"

nexus_uplink:
  enabled: true
  hub_address: "10.240.0.10"
  hub_port: 50051
  heartbeat_interval_sec: 5
  tls_enabled: true
  ca_certificate: "/etc/sentinel/certs/nexus_ca.crt"
  client_certificate: "/etc/sentinel/certs/appliance.crt"
  client_private_key: "/etc/sentinel/certs/appliance.key"
```

---

## 2. Generating Self-Signed SSL Certificates for Port 8443

To access the local web command center immediately, generate a self-signed certificate:

```bash
sudo mkdir -p /etc/sentinel/certs
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/sentinel/certs/server.key \
    -out /etc/sentinel/certs/server.crt \
    -subj "/C=DE/ST=Bavaria/L=Munich/O=Aryorithm/CN=edge-substation-alpha"
sudo chmod 600 /etc/sentinel/certs/server.key
```

---

## 3. Validating the Configuration

Verify syntax and file paths before restarting the daemon:

```bash
sentinel --validate-config /etc/sentinel/sentinel.yaml
```

### Expected Output
```text
[+] Parsing /etc/sentinel/sentinel.yaml: OK
[+] Checking network interface eth0: FOUND (Link UP)
[+] Verifying eBPF bytecode /usr/local/lib/bpf/xdp_filter.o: VALID ELF
[+] Checking AI model /opt/sentinel/models/network_threat_v2.onnx: VALID (SHA-256 Verified)
[+] Configuration is structurally sound. Daemon ready for launch.
```
```

---

### File: `blackbox-sentinel/docs/getting-started/shadow-mode-evaluation.md`

```markdown
# 14-Day Zero-Risk Passive SPAN Evaluation (`STAGE_SHADOW_MODE`)

In municipal water plants, nuclear substations, and automotive manufacturing lines, deploying an unverified inline security agent risks unexpected disruption. 

To eliminate operational risk, `blackbox-sentinel` supports **`STAGE_SHADOW_MODE`**: a completely passive evaluation mode designed for 14-day zero-risk network audits.

---

## 1. SPAN Port / Network TAP Topology

```text
 [ Industrial Ethernet Switch ]
        │
        ├── Port 1: Engineering Workstation ──► [ PLC / Field Device ]
        │
        └── Port 8 (SPAN / Mirror Port): Copies 100% of packets
               │
               ▼ Passive Ingress (No Inline Risk)
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Appliance (STAGE_SHADOW_MODE)             │
 │  - Protocol Dissectors decode Modbus / S7 / DNP3            │
 │  - AI Autoencoder scores anomalies in RAM                   │
 │  - Zero Inline Disruption: XDP Filter returns XDP_PASS ONLY │
 │  - Emits XAI Feature Attributions & Compliance Scorecard    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Configuring Shadow Mode

Set the operational stage in `/etc/sentinel/sentinel.yaml`:

```yaml
appliance:
  deployment_stage: "STAGE_SHADOW_MODE"
```

Restart the daemon:

```bash
sudo systemctl restart sentinel
```

---

## 3. Shadow Audit Guarantees

* **Zero Packet Drops:** The in-kernel eBPF filter will **never** return `XDP_DROP`. All packets pass unhindered.
* **Passive Traffic Reflection:** The appliance does not transmit synthetic packets onto the wire unless deception decoys are explicitly enabled.
* **Full Forensic Telemetry:** All 26 native subsystems execute in full evaluation mode. Detections, XAI feature attributions, and anomaly traces are stored in local SIEM memory and visible on the Web Command Center (port 8443).
```

---

### File: `blackbox-sentinel/docs/getting-started/first-threat-mitigation.md`

```markdown
# Verifying Your First In-Kernel Threat Mitigation

Once shadow evaluation is complete and baseline parameters are tuned, transition the appliance to **`STAGE_FULL_ACTIVE`** to enable autonomous in-kernel packet drops ($< 0.84\,\mu\text{s}$).

---

## 1. Transitioning to Active Defense

Edit `/etc/sentinel/sentinel.yaml`:

```yaml
appliance:
  deployment_stage: "STAGE_FULL_ACTIVE"
```

Reload the daemon:

```bash
sudo systemctl restart sentinel
```

---

## 2. Triggering a Test Threat

Simulate a rapid Modbus register override attack or port sweep from a test workstation (`198.51.100.42`):

```bash
# From adversary test terminal
curl http://<APPLIANCE_IP>:502/test_attack_vector
```

---

## 3. Inspecting the Live Kernel Drop

Query the in-kernel drop table directly via CLI:

```bash
sentinel --dump-drops
```

### Expected Output

```text
================================================================================
                    ACTIVE IN-KERNEL eBPF DROP TABLE
================================================================================
Target IPv4      Rule ID   Triggering Subsystem   Drop Count   TTL Remaining
198.51.100.42    1802      18_cps_sec (Modbus)    1,421 pkts   54 seconds
--------------------------------------------------------------------------------
Last Mitigation Latency : 0.82 µs (In-Kernel Driver Space)
Socket Buffer Overhead  : 0 bytes allocated
```

Notice that the packets were purged directly inside the driver ring: the host operating system's connection pool never registers open TCP sockets.
```

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