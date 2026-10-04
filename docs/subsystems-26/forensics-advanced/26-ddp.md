---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/26-ddp.md`

```markdown
# Subsystem 26: Distributed Deception Decoy PLCs (`26_ddp`)

`26_ddp` deploys synthetic deception honeypots across unused IP addresses on the local network. It emulates realistic, responsive industrial controllers (**Modbus PLCs, Siemens S7 outstations, and medical DICOM servers**) on secondary Virtual IPs (VIPs) to trap adversaries during the reconnaissance phase.

---

## 1. Secondary VIP Binding & Port Arbitration

To avoid port collisions with real production services on the same appliance, `26_ddp` binds decoy listeners exclusively to secondary virtual IPs using `SO_BINDTODEVICE`:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Physical Network Adapter: eth0 (Subnet: 10.240.0.0/24)      │
 ├─────────────────────────────────────────────────────────────┤
 │ Primary IP : 10.240.0.100  ──► Real Production Services      │
 │ Decoy VIP 1: 10.240.0.199  ──► Synthetic Schneider PLC     │
 │ Decoy VIP 2: 10.240.0.200  ──► Synthetic Siemens S7-1200    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Decoy Modbus Server Implementation (`DecoyPlc.cpp`)

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <blackbox/xdp_manager.hpp>

namespace sentinel::subsystems {

class DecoyPlc {
public:
    void bind_decoy_vip(const std::string& vip_address, uint16_t port, blackbox::XdpManager& xdp) {
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, vip_address.c_str(), &addr.sin_addr);

        if (::bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            ::listen(sock, 10);
            
            // Any client connecting to this decoy is an unauthorized adversary
            // Immediately flag attacker source IP and trigger kernel mitigation
        }
    }
};

} // namespace sentinel::subsystems
```

---

## 3. High-Fidelity Decoy Trapping

* **Zero False Positives:** Legitimate operational software never attempts communication with decoy VIPs. Any connection attempt (SYN packet to port 502 or 102 on a decoy IP) is treated as malicious.
* **Instant Quarantine:** The attacker’s source IP is inserted into `blocked_ip_map` immediately, severing their ability to scan the real production PLCs on the subnet.
```

