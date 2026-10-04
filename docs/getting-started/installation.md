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