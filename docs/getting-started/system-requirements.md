# System Requirements & Prerequisites

Review the toolchain, kernel dependencies, and hardware privileges before running `blackbox-sentinel`.

---

## 1. Operating System Baseline

`blackbox-sentinel` is compiled and verified against modern Linux server baselines:

* **Recommended OS:** Ubuntu 24.04 LTS (Noble Numbat) or Ubuntu 26.04 (Devel).
* **Linux Kernel:** Kernel version **>= 6.8** (Minimum: 5.15 LTS with backported BTF).
* **C Library:** GNU C Library (`glibc`) version **>= 2.35** (Verified up to `glibc 2.43`).

---

## 2. Required Linux Kernel Subsystems

Ensure the following kernel configuration flags are set to `=y` in your running kernel:

```bash
# Verify kernel capabilities
cat /boot/config-$(uname -r) | grep -E 'CONFIG_BPF|CONFIG_XDP|CONFIG_NET_CLS_ACT'
```

* `CONFIG_BPF=y` & `CONFIG_BPF_SYSCALL=y`: Core eBPF engine.
* `CONFIG_BPF_JIT=y`: Native instruction JIT compiler.
* `CONFIG_DEBUG_INFO_BTF=y`: BPF Type Format for CO-RE portability.
* `CONFIG_XDP_SOCKETS=y`: High-speed AF_XDP packet transport.

---

## 3. Network Hardware Privileges (`Capabilities`)

When running `sentinel` as a dedicated non-root service user, grant the following POSIX Linux capabilities:

```bash
sudo setcap 'cap_net_admin,cap_net_raw,cap_bpf,cap_sys_resource=+ep' /usr/local/bin/sentinel
```

* **`CAP_NET_ADMIN`:** Required to attach eBPF programs to network device hooks.
* **`CAP_NET_RAW`:** Required to open promiscuous raw sockets and inspect raw frames.
* **`CAP_BPF`:** Required to load BPF bytecode and allocate maps.
* **`CAP_SYS_RESOURCE`:** Required to pin memory pages (`mlock`) without `ulimit -l` bounds.

