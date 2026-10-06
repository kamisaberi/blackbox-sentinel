# Deploying a 15-Minute Non-Intrusive SPAN Shadow Audit

This tutorial demonstrates how to deploy `blackbox-sentinel` in a completely passive, zero-risk evaluation mode using an industrial network switch mirror port (SPAN). In this configuration, the appliance observes and scores live traffic without modifying network packets or dropping flows.

---

## 1. Network Topology: Passive Mirroring

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Industrial Managed Switch (e.g. Hirschmann / Cisco IE3400)  │
 ├─────────────────────────────────────────────────────────────┤
 │ Port 1: SCADA HMI Host      ──► Port 2: Siemens S7-1500 PLC │
 │ Port 8 (SPAN / Mirror Port) : Copies 100% of Port 1 & 2 Rx/Tx│
 └──────────────────────────────┬──────────────────────────────┘
                                │ Physical Patch Cable
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Blackbox-Sentinel Appliance (Interface: eth1)               │
 │  - Deployment Stage: STAGE_SHADOW_MODE                      │
 │  - Evaluates traffic through all 26 subsystems in RAM       │
 │  - eBPF Filter returns XDP_PASS ONLY (Zero Packet Drops)    │
 │  - Real-Time Web Console active on eth0 (Port 8443 HTTPS)   │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Appliance Configuration (`/etc/sentinel/sentinel.yaml`)

Configure `eth1` as the passive sniffing interface and set the operational stage to `STAGE_SHADOW_MODE`:

```yaml
version: "1.0.0"

appliance:
  node_name: "substation-shadow-auditor"
  deployment_stage: "STAGE_SHADOW_MODE" # Enforces zero packet drops
  log_level: "INFO"

network:
  primary_interface: "eth1"
  promiscuous_mode: true
  xdp_attach_mode: "DRIVER" # Native driver mode for wire-speed parsing
  bpf_filter_path: "/usr/local/lib/bpf/xdp_filter.o"

web_console:
  enabled: true
  bind_address: "192.168.1.100" # Management interface IP (eth0)
  port: 8443
```

---

## 3. Deployment Steps

```bash
# 1. Bring up the SPAN interface in promiscuous mode
sudo ip link set dev eth1 promisc on up

# 2. Validate configuration
sentinel --validate-config /etc/sentinel/sentinel.yaml

# 3. Start the daemon under systemd
sudo systemctl restart sentinel
```

---

## 4. Inspecting Audit Results

Open your browser and navigate to **`https://192.168.1.100:8443`**. 

During the 14-day audit window, the dashboard presents:
* Full asset discovery across Modbus, S7, DNP3, and IEC 104 devices.
* Behavioral baseline deviations recorded by Subsystem `02_ueba`.
* Physical invariant warnings flagged by Subsystem `18_cps_sec`.
* Comprehensive compliance gap analysis exportable as an audit PDF.

