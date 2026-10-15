Here is the complete reference guide and command-by-command instructions to download certified malware **PCAPs**, research **SLAB datasets**, and digital twin **scenarios** using both **`sentinel-ctl`** and **`sentinel-matrix`**.

Both tools use the **Cache-First Engine** (`/var/cache/sentinel/`), checking local storage first before downloading and automatically managing runtime paths.

---

# Method 1: Using `sentinel-ctl` (Appliance & Edge Client)

The `sentinel-ctl` utility manages dependencies, PCAP captures, and research datasets directly from the command line.

```text
========================================================================================================
                               SENTINEL-CTL RESOURCE DOWNLOAD WORKFLOW
========================================================================================================
 Command: sentinel-ctl pcap pull <slug>       ──► Staged to: /etc/sentinel/pcaps/
 Command: sentinel-ctl dataset pull <slug>    ──► Staged to: /etc/sentinel/datasets/
 Command: sentinel-ctl sync <routes.yaml>     ──► Resolves all .spkg packages & ONNX models
========================================================================================================
```

### 1. Download Certified Malware PCAPs
Fetch ground-truth binary captures into `/etc/sentinel/pcaps/`:

```bash
cd /home/kami/blackbox-sentinel/build

# 1. Download Industroyer2 IEC-104 Substation Breaker Trip
sudo ./sentinel-ctl pcap pull industroyer2_substation.pcap

# 2. Download TRITON / Trisis TriStation 1131 SIS Safety Override
sudo ./sentinel-ctl pcap pull triton_trisis_sis.pcap

# 3. Download Stuxnet Siemens S7Comm Ladder Logic Injection
sudo ./sentinel-ctl pcap pull stuxnet_s7comm_injected.pcap

# 4. Download Modbus UIUC SCADA Actuator Oscillation Capture
sudo ./sentinel-ctl pcap pull modbus_uiuc_scada_attack.pcap

# 5. Download HTTP/2 Rapid Reset DoS Capture (CVE-2023-44487)
sudo ./sentinel-ctl pcap pull cve_2023_44487_rapid_reset.pcap
```

#### Verify Downloaded PCAPs:
```bash
ls -lh /etc/sentinel/pcaps/
```

---

### 2. Download SLAB Universal Wire Protocol Research Datasets
Download zero-copy binary datasets (`[0x534C4142 | EventID | Label | Dim | Tensor]`) into `/etc/sentinel/datasets/` for `sentinel-lab` line-rate streaming:

```bash
cd /home/kami/blackbox-sentinel/build

# 1. Download CIC-IDS-2017 PortScan (32-dimensional, 81 MB)
sudo ./sentinel-ctl dataset pull cicids2017_portscan.slab

# 2. Download UNSW-NB15 Cyber-Physical Stream (42-dimensional, 125 MB)
sudo ./sentinel-ctl dataset pull unsw_nb15_cps.slab
```

#### Verify Downloaded SLAB Datasets:
```bash
ls -lh /etc/sentinel/datasets/
# Inspect SLAB binary magic header (0x534C4142):
hexdump -C /etc/sentinel/datasets/cicids2017_portscan.slab | head -n 2
```

---

### 3. Automatically Download All Profile Resources (`sync`)
To download every `.spkg` package and ONNX model required by your active routing specification in one command:

```bash
cd /home/kami/blackbox-sentinel/build
sudo ./sentinel-ctl sync ../configs/model_routes.yaml
```

---

### 4. Inspect or Manage the Local Cache
Inspect all cached resources or export them to a USB drive for offline air-gapped facilities:

```bash
cd /home/kami/blackbox-sentinel/build

# List all downloaded assets currently cached locally
./sentinel-ctl cache list

# Export an offline bundle for USB transfer to an air-gapped plant
./sentinel-ctl cache export /tmp/airgap_assets_bundle.tar.gz
```

---

# Method 2: Using `sentinel-matrix` (Cyber-Range Digital Twin)

Inside `sentinel-matrix`, you can pull and stage resources using `make` commands or the `matrix-ctl` utility.

```text
========================================================================================================
                              SENTINEL-MATRIX RESOURCE DOWNLOAD WORKFLOW
========================================================================================================
 Target: make sync-hub-pcaps             ──► Synchronizes all PCAPs into shared/datasets/
 Target: make scenario-pull NAME=<slug>  ──► Unpacks complete 8-node digital twin scenario
 Target: make download-pcaps             ──► Resolves raw PCAPs via tools/download_real_pcaps.py
========================================================================================================
```

### 1. Download & Sync All Certified PCAPs
Populate `sentinel-matrix/shared/datasets/` with the certified malware captures from the cache:

```bash
cd /home/kami/sentinel-matrix

# Pull & synchronize all certified PCAPs in one step
make sync-hub-pcaps
```

#### Verify Staged PCAPs in Matrix:
```bash
ls -lh shared/datasets/*.pcap
```

---

### 2. Pull 1-Click Digital Twin Scenarios
Download and unpack complete multi-node scenarios (Docker Compose topologies, network configurations, and attack automation scripts) into `configs/active_scenario/`:

```bash
cd /home/kami/sentinel-matrix

# Option A: Pull the Power Substation Blackout Scenario (IEC-104 + Substation Alpha)
make scenario-pull NAME=power_grid_blackout

# Option B: Pull the Hospital PACS Heist Scenario (DICOM PHI + Ransomware Entropy)
make scenario-pull NAME=hospital_pacs_heist

# Option C: Pull the Refinery Disaster Scenario (TRITON Triconex SIS Sabotage)
make scenario-pull NAME=refinery_disaster_triton
```

#### Inspect Unpacked Active Scenario:
```bash
cat configs/active_scenario/configs/topology.yaml
ls -la configs/active_scenario/scripts/
```

---

### 3. Replay Downloaded Assets Across the Live Range
Once downloaded, stream the packets live over the virtual network (`10.240.0.0/24`) to test in-kernel drops ($0.84\,\mu\text{s}$) and web dashboard updates:

```bash
cd /home/kami/sentinel-matrix

# 1. Replay Industroyer2 attack against Substation Node (.101)
make attack-hub-industroyer2

# 2. Replay TRITON attack against Hospital PACS Node (.102)
make attack-hub-triton

# 3. Replay Stuxnet attack against Refinery Node (.103)
make attack-hub-s7

# 4. Or execute the active scenario attack script:
make scenario-run
```

---

### Quick Diagnostic: Check What is Installed vs. Cached

Run the status check at any time:

```bash
# In blackbox-sentinel:
/home/kami/blackbox-sentinel/build/sentinel-ctl status

# In sentinel-matrix:
/home/kami/sentinel-matrix/tools/matrix_ctl.sh status
```