# In-Kernel eBPF Driver Attachment Issues

This guide resolves network interface binding failures and eBPF hook rejections across physical and virtual network adapters.

---

## 1. `Operation not supported` on Virtual Adapters (`ens33`, `vmxnet3`)

### Symptom
```text
[FATAL] XdpManager: Failed to attach xdp_filter.o to interface ens33 in DRIVER mode: Operation not supported (errno 95)
```

### Causes & Remediation
1. **Conflicting Hardware Offloads:** The VMware `vmxnet3` driver blocks native XDP if Large Receive Offload (LRO) or Generic Receive Offload (GRO) is active. Disable them via `ethtool`:
   ```bash
   sudo ethtool -K ens33 lro off gro off rxvlan off txvlan off
   ```
2. **MTU Exceeds Driver Page Bounds:** If MTU is greater than 1500, native XDP allocation will fail:
   ```bash
   sudo ip link set dev ens33 mtu 1500
   ```
3. **Fallback to Generic SKB Mode:** If native driver mode remains unsupported on legacy virtual hardware, switch the operational mode in `/etc/sentinel/sentinel.yaml`:
   ```yaml
   network:
     xdp_attach_mode: "SKB"
   ```

---

## 2. `Device or resource busy (-EBUSY)`

### Symptom
```text
[ERROR] XdpManager: Interface eth0 already has an active XDP program attached.
```

### Remediation
Force-clear any orphaned or crashed XDP programs:

```bash
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth0 xdpgeneric off
```

Then restart `sentinel`:

```bash
sudo systemctl restart sentinel
```

