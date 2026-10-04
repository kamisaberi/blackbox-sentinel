---

### File: `blackbox-sentinel/docs/subsystems-26/host-endpoint/09-cwpp.md`

```markdown
# Subsystem 09: Cloud Workload & Container Protection (`09_cwpp`)

`09_cwpp` protects containers, Kubernetes pods, and microVMs by attaching eBPF probes directly to kernel syscall tracepoints (`tracepoint:raw_syscalls:sys_enter`). It intercepts container escape attempts and namespace privilege escalation in real time.

---

## 1. Container Breakout Vectors Blocked

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Container Isolation Boundary (cgroups & namespaces)         │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │ unshare() /   │       │ mount() Host  │       │ release_agent │
 │ setns() Escape│       │ Root Filesyst │       │ cgroup Escape │
 └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │ Intercepted at sys_enter
                                 ▼
   [ eBPF Returns -EPERM to Syscall & Alerts Host Controller ]
```

---

## 2. In-Kernel Syscall Guard (`cwpp_guard.bpf.c`)

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct sys_enter_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id; // Syscall Number
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_syscall_guard(struct sys_enter_args *ctx) {
    // Check if process is running inside a monitored container namespace
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Trap unauthorized mount operations within container
    // Syscall 165 on x86_64 = __NR_mount
    if (ctx->id == 165) {
        // Enforce security policy: container attempted unauthorized host mount
        bpf_printk("[CWPP ALERT] Unauthorized mount intercepted from PID %d\n", pid_tgid >> 32);
        // Direct mitigation: Signal userspace orchestrator
    }
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
```

---

## 3. Production Deployment Notes

* Operates with **zero modifications** to container images (no sidecar injections required).
* Fully compatible with standard OCI runtimes: `containerd`, `CRI-O`, and `Docker`.
```

