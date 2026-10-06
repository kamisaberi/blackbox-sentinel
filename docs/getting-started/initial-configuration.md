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

