# Subsystem 06: Endpoint Detection & Response (`06_edr`)

`06_edr` provides local endpoint telemetry, process lineage reconstruction, and memory injection detection. It interfaces with the Linux kernel via the **Netlink Process Event Connector** (`cn_proc`) and Linux `/proc` filesystem auditing, maintaining an in-memory Directed Acyclic Graph (DAG) of all running processes.

---

## 1. Process Lineage & Memory Injection Mechanics

```text
 [ Linux Kernel: fork / exec / exit / ptrace ]
                       │
                       ▼ Linux Netlink Connector (NETLINK_CONNECTOR)
 ┌─────────────────────────────────────────────────────────────┐
 │ 06_edr Netlink Receiver Thread                              │
 │   - Zero Polling: Event-driven notification on process life │
 └─────────────────────┬───────────────────────────────────────┘
                       │
                       ▼ Update In-Memory Process Tree DAG
 ┌─────────────────────────────────────────────────────────────┐
 │ Process Lineage DAG (Statically Pre-Allocated)              │
 │   - Systemd (PID 1) ──► Nginx (PID 1024) ──► /bin/bash (PID 4096)
 └─────────────────────┬───────────────────────────────────────┘
                       │
                       ▼ Behavioral Anomaly Rules
 ┌─────────────────────────────────────────────────────────────┐
 │ Threat Traps:                                               │
 │  • Shell spawned from Web Server or SCADA Runtime           │
 │  • Process Hollowing (Memory map delta vs. Disk binary)     │
 │  • ptrace injection against critical sentinel worker threads │
 └─────────────────────┬───────────────────────────────────────┘
                       │
                       ▼ Action
 [ SIGKILL Attacker Process & Alert SIEM in < 2.5 µs ]
```

---

## 2. Netlink Process Connector Interface (`EdrEngine.cpp`)

```cpp
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

namespace sentinel::subsystems {

class EdrEngine {
public:
    void init_netlink_listener() {
        nl_sock_ = ::socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
        if (nl_sock_ < 0) {
            throw std::runtime_error("Failed to open Netlink process connector socket");
        }

        struct sockaddr_nl sa{};
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = CN_IDX_PROC;
        sa.nl_pid = getpid();

        if (::bind(nl_sock_, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
            ::close(nl_sock_);
            throw std::runtime_error("Failed to bind Netlink socket");
        }

        // Subscribe to process events
        subscribe_proc_events(true);
    }

    void process_event(const struct proc_event& ev) {
        switch (ev.what) {
            case PROC_EVENT_EXEC:
                evaluate_exec_anomaly(ev.event_data.exec.process_pid, ev.event_data.exec.process_tgid);
                break;
            case PROC_EVENT_PTRACE:
                flag_memory_tampering(ev.event_data.ptrace.process_pid, ev.event_data.ptrace.tracer_pid);
                break;
            default:
                break;
        }
    }

private:
    int nl_sock_{-1};
    void subscribe_proc_events(bool enable);
    void evaluate_exec_anomaly(pid_t pid, pid_t tgid);
    void flag_memory_tampering(pid_t target, pid_t tracer);
};

} // namespace sentinel::subsystems
```

---

## 3. Threat Mitigation SLAs

* **Process Discovery Latency:** $< 15\,\mu\text{s}$ from kernel `execve` syscall to DAG node binding.
* **Process Termination Action:** Emits targeted `SIGKILL` directly through kernel syscalls before malicious payload execution completes.

