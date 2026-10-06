# In-Kernel eBPF Drop Table Management

The Web Command Center provides administrators with direct visibility into the active in-kernel **`blocked_ip_map`**, allowing operators to monitor automated mitigations, inspect remaining TTL durations, and execute **1-click manual unblocks**.

---

## 1. Drop Table Web Interface

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ ACTIVE IN-KERNEL MITIGATION RULES (Total Active: 2)                         │
 ├────────────────┬──────────┬──────────────┬──────────────┬─────────┬─────────┤
 │ Target IPv4    │ Rule ID  │ Subsystem    │ Packets Drop │ TTL Left│ Action  │
 ├────────────────┼──────────┼──────────────┼──────────────┼─────────┼─────────┤
 │ 198.51.100.42  │ 1802     │ 18_cps_sec   │ 12,891 pkts  │ 42s     │[UNBLOCK]│
 │ 203.0.113.88   │ 0401     │ 04_ids_ips   │ 1,402 pkts   │ 184s    │[UNBLOCK]│
 └────────────────┴──────────┴──────────────┴──────────────┴─────────┴─────────┘
```

---

## 2. The 1-Click Unblock API Flow

When an administrator clicks **`[UNBLOCK]`**:

```text
 Operator Clicks [UNBLOCK] in Web Dashboard
                   │
                   ▼ HTTP POST /api/v1/drops/unblock
 ┌─────────────────────────────────────────────────────────────┐
 │ Web API Handler validates JWT Bearer Authorization Token    │
 └─────────────────┬───────────────────────────────────────────┘
                   │ Invokes blackbox::XdpManager::unblock_ip()
                   ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Linux Kernel: BPF_MAP_DELETE_ELEM Syscall                   │
 │   - Map: /sys/fs/bpf/blackbox/blocked_ip_map                │
 │   - Execution Latency: ~140 nanoseconds                     │
 └─────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
 [ Source IP unblocked immediately; subsequent packets pass ]
```

---

## 3. C++ Unblock Handler Implementation

```cpp
void handle_unblock_request(const HttpRequest& req, HttpResponse& resp, blackbox::XdpManager& xdp) {
    if (!validate_jwt_admin_claim(req.get_header("Authorization"))) {
        resp.set_status(401, "Unauthorized");
        return;
    }

    uint32_t ip = parse_ipv4_param(req.json()["ipv4"].get<std::string>());
    
    // Direct kernel syscall to remove entry from BPF map
    xdp.unblock_ip(ip);

    resp.set_status(200, "OK");
    resp.set_json({{"status", "UNBLOCKED"}, {"ipv4_net", ip}});
}
```

