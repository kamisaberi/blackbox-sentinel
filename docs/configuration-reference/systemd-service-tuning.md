# Systemd Service Configuration & Real-Time Tuning

To maintain sub-microsecond packet mitigation latencies, the `sentinel` daemon must be scheduled with real-time process priority, protected against kernel out-of-memory (OOM) killing, and granted specific Linux capabilities.

---

## 1. Production Systemd Unit File (`/etc/systemd/system/sentinel.service`)

```ini
[Unit]
Description=Aryorithm Blackbox-Sentinel Cyber-Physical Edge XDR Appliance
Documentation=https://docs.aryorithm.com/sentinel/
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# Executable Path
ExecStart=/usr/local/bin/sentinel --config /etc/sentinel/sentinel.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3s

# ==============================================================================
# REAL-TIME SCHEDULER & CPU TUNING
# ==============================================================================
# Use Round-Robin Real-Time Scheduler with priority 98
CPUSchedulingPolicy=rr
CPUSchedulingPriority=98
Nice=-20

# Protect against Linux OOM killer under heavy DDoS floods
OOMScoreAdjust=-1000

# ==============================================================================
# MEMORY & RESOURCE LIMITS
# ==============================================================================
# Allow unlimited locked physical memory for eBPF and AF_XDP UMEM pools
LimitMEMLOCK=infinity
LimitNOFILE=1048576
LimitNPROC=65536

# ==============================================================================
# LINUX CAPABILITIES RESTRICTION
# ==============================================================================
# Grant required network and BPF privileges
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_RESOURCE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_BPF CAP_SYS_RESOURCE CAP_SYS_PTRACE

# Sandboxing Protections
ProtectHome=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## 2. Deploying and Verifying Real-Time Priority

Apply the unit file and reload systemd:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sentinel
```

Verify that the process is running under the real-time scheduler (`SCHED_RR`):

```bash
chrt -p $(pgrep sentinel)
```

### Expected Output
```text
pid 14022's current scheduling policy: SCHED_RR
pid 14022's current scheduling priority: 98
```

