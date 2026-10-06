# Deploying Deception Honeypot PLCs on Secondary VIPs (`26_ddp`)

This tutorial guides you through setting up synthetic deception honeypots using Subsystem `26_ddp`. The appliance binds responsive decoy Modbus and Siemens S7 controllers to **secondary Virtual IPs (VIPs)** without conflicting with legitimate control systems on the primary interface.

---

## 1. Virtual IP & Deception Topology

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Physical Subnet: 10.240.0.0/24                              │
 ├─────────────────────────────────────────────────────────────┤
 │ Primary IP : 10.240.0.100  ──► Real Production Modbus Master│
 │ Decoy VIP 1: 10.240.0.199  ──► Synthetic Schneider M340 PLC │
 │ Decoy VIP 2: 10.240.0.200  ──► Synthetic Siemens S7-1200 PLC│
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Configuring Deception Decoys in `sentinel.yaml`

```yaml
subsystems:
  ddp:
    enabled: true
    auto_bind_vips: true
    parent_interface: "eth0"
    decoys:
      # Decoy 1: Emulated Schneider Modicon M340
      - virtual_ip: "10.240.0.199"
        netmask: "255.255.255.0"
        alias_label: "eth0:1"
        protocol: "MODBUS_TCP"
        port: 502
        banner: "Schneider Electric Modicon M340 V2.4"
        quarantine_attacker: true
        quarantine_duration_seconds: 3600

      # Decoy 2: Emulated Siemens S7-1200
      - virtual_ip: "10.240.0.200"
        netmask: "255.255.255.0"
        alias_label: "eth0:2"
        protocol: "S7COMM"
        port: 102
        banner: "Siemens S7-1200 CPU 1214C"
        quarantine_attacker: true
        quarantine_duration_seconds: 3600
```

Restart the appliance:

```bash
sudo systemctl restart sentinel
```

Verify that the secondary VIPs are bound to `eth0`:

```bash
ip addr show dev eth0
```

---

## 3. Simulating Adversary Reconnaissance with Nmap

From an external workstation, run an industrial network scan targeting the decoy IP:

```bash
nmap -sS -p 502,102 10.240.0.199
```

### Result
1. The decoy listener acknowledges the connection handshake, confirming port 502 is open.
2. Because legitimate factory operations never communicate with `10.240.0.199`, `26_ddp` flags the scanning host as an adversary.
3. The attacker's source IP is inserted into `blocked_ip_map` immediately:

```text
[!] DECEPTION HONEYPOT TRIGGERED:
    Attacker IP : 10.240.0.88
    Decoy Target: 10.240.0.199:502 (Schneider M340 Decoy)
    Action      : Source IP blocked in kernel driver space for 1 hour.
    Impact      : Attacker blinded from discovering real production PLCs on subnet.
```

