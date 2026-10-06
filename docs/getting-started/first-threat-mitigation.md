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

