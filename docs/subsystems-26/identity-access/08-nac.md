# Subsystem 08: Network Access Control (`08_nac`)

`08_nac` controls device admission and dynamic VLAN isolation on local industrial switches. It functions as an inline **802.1X / RADIUS Change of Authorization (CoA)** controller, dynamically quarantining rogue devices or infected PLCs.

---

## 1. Dynamic Quarantine Architecture

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ 08_nac Dynamic Controller                                   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Threat Detected (Subsystems 01-26)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ RADIUS Change of Authorization (RFC 5176 CoA-Request)       │
 │   - Dispatched to Managed Switch (Cisco, Hirschmann, Moxa)  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Switch Reassigns Port
 ┌─────────────────────────────────────────────────────────────┐
 │ Port Switched: VLAN 10 (Production) ──► VLAN 999 (Quarantine)│
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Linux Bridge Interface VLAN Steering

On multi-homed appliances configured as an inline bridge (`br0`), `08_nac` controls the Linux kernel bridge forwarding table (`fdb`) directly via Netlink:

```cpp
#include <linux/rtnetlink.h>
#include <net/if.h>

void quarantine_mac_address(int bridge_ifindex, const uint8_t mac[6], uint16_t quarantine_vlan) {
    // Issues RTM_NEWNEIGH / RTM_SETLINK netlink message
    // Forces switch port/bridge egress to quarantine VLAN tag 999
}
```

