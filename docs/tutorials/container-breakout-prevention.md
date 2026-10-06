# Preventing Container Breakouts with eBPF CWPP (`09_cwpp`)

This tutorial demonstrates how Subsystem `09_cwpp` intercepts container escapes and namespace privilege escalation attempts in Docker and Kubernetes clusters by tracking syscalls at `tracepoint:raw_syscalls:sys_enter`.

---

## 1. Attack Scenario: Host Filesystem Mount Escape

An attacker compromises an unprivileged container running a vulnerable web application and attempts to break out of the container namespace by mounting the host's root block device (`/dev/sda1`):

```bash
# Attacker command inside compromised container
mkdir /mnt/host && mount /dev/sda1 /mnt/host
```

---

## 2. Enabling Subsystem `09_cwpp`

Ensure `09_cwpp` is enabled in `/etc/sentinel/sentinel.yaml`:

```yaml
subsystems:
  cwpp:
    enabled: true
    monitor_container_namespaces: true
    trap_host_mount_escapes: true
    trap_unshare_privilege_escalation: true
    trap_cgroup_release_agent: true
    action: "TERMINATE_CONTAINER_PROCESS"
```

---

## 3. Executing the Test Inside Docker

Launch an isolated test container:

```bash
docker run --rm -it --cap-add=SYS_ADMIN alpine sh
```

Inside the container shell, attempt the mount breakout:

```bash
mkdir /tmp/escape && mount /dev/sda1 /tmp/escape
```

### Observation & Result
The `mount` syscall is intercepted in kernel space by `cwpp_guard.bpf.c`:
1. The kernel tracepoint returns `-EPERM` (Operation not permitted).
2. `09_cwpp` sends an immediate `SIGKILL` to the offending process PID inside the container.
3. The containerized shell terminates with:

```text
Killed
```

### Sentinel Appliance Log
```text
[CWPP ALERT] Container Escape Attempt Intercepted:
    Container ID : c8f2b3e104a1
    Syscall      : __NR_mount (165)
    Target Device: /dev/sda1 -> /tmp/escape
    Action       : Syscall neutralized with -EPERM; PID 18402 terminated via SIGKILL.
```

