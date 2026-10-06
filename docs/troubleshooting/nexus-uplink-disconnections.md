# Nexus Fleet Uplink Disconnection Diagnostics

This guide covers troubleshooting network drops, mTLS handshake rejections, and gRPC timeouts between `blackbox-sentinel` and `sentinel-nexus`.

---

## 1. gRPC Status: `UNAVAILABLE (14)`

### Symptom
```text
[WARN] NexusUplink: gRPC connection to 10.240.0.10:50051 failed: 14: Socket failed to connect to all addresses
```

### Diagnosis Checklist
1. **Network Connectivity:** Test TCP layer reachability to port 50051:
   ```bash
   nc -zv 10.240.0.10 50051
   ```
2. **Firewall Blocking:** Ensure intermediate firewalls allow bidirectional traffic over TCP port 50051.
3. **Hub Service Health:** Verify that the `sentinel-nexus` daemon is running on the central server:
   ```bash
   sudo systemctl status sentinel-nexus
   ```

---

## 2. mTLS Handshake Rejection (`UNAUTHENTICATED (16)`)

### Symptom
```text
[ERROR] NexusUplink: mTLS Handshake failed: 16: SSL_ERROR_SSL: certificate verify failed
```

### Causes & Fixes
1. **Clock Drift:** If the appliance system time deviates by more than $300\text{ seconds}$ from the Nexus hub, certificate validity checks will fail. Synchronize clocks via NTP:
   ```bash
   sudo chronyc makestep
   ```
2. **Expired Client Certificate:** Check the expiration timestamp of `/etc/sentinel/certs/appliance.crt`:
   ```bash
   openssl x509 -in /etc/sentinel/certs/appliance.crt -noout -enddate
   ```
   If expired, re-run the hardware enrollment handshake to obtain an updated signed certificate lease.

