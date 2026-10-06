# Environment Variable Overrides

Any parameter in `/etc/sentinel/sentinel.yaml` can be overridden at runtime using environment variables. This enables dynamic tuning inside containerized testbeds (`sentinel-matrix`) and automated CI/CD deployments.

---

## 1. Supported Environment Variables

| Variable Name | YAML Path Equivalent | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `SENTINEL_CONFIG_PATH` | N/A | `/etc/sentinel/sentinel.yaml` | Primary path to configuration manifest. |
| `NODE_IDENTIFIER` | `appliance.node_name` | Hostname | Appliance fleet node identifier. |
| `DEPLOYMENT_STAGE` | `appliance.deployment_stage` | `STAGE_FULL_ACTIVE` | Operational stage. |
| `LOG_LEVEL` | `appliance.log_level` | `INFO` | Console logging verbosity (`DEBUG`, `INFO`). |
| `PRIMARY_INTERFACE` | `network.primary_interface` | `eth0` | Network device for eBPF attachment. |
| `XDP_MODE` | `network.xdp_attach_mode` | `DRIVER` | Driver mode: `DRIVER` or `SKB`. |
| `NEXUS_HOST` | `nexus_uplink.hub_address` | `10.240.0.10` | IP of Tier 6 Sentinel-Nexus Hub. |
| `NEXUS_PORT` | `nexus_uplink.hub_port` | `50051` | gRPC fleet port. |
| `WEB_PORT` | `web_console.port` | `8443` | Local administrative web port. |
| `OFFLINE_MODE` | N/A | `0` | If `1`, disables all network resolution. |

---

## 2. Precedence Order

When starting up, `sentinel` resolves configuration values using the following priority order (highest to lowest):

1. **CLI Flags** (e.g., `--interface eth1`)
2. **Environment Variables** (e.g., `PRIMARY_INTERFACE=eth1`)
3. **YAML File Entries** (`/etc/sentinel/sentinel.yaml`)
4. **Compiled Defaults** (Internal fallback constants)

