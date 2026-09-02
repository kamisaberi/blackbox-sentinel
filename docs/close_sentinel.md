There are 3 easy ways to cleanly close or stop **`sentinel`**:

---

### Option 1: Keyboard Shortcut (If running in your active terminal)

Press **`Ctrl + C`** in the terminal window where `./sentinel` is running.

`sentinel` has a built-in signal handler (`SIGINT`) that will catch this and shut down all background threads, WebSockets, REST servers, and shared libraries gracefully:

```text
^C
[Blackbox Sentinel] Shutting down appliance service...
[libblackbox.so] Engine processing loop stopped.
[Blackbox Sentinel] Service Stopped Gracefully.
```

---

### Option 2: Kill Command (From another terminal window)

If `sentinel` is running in the background or another terminal, open a new terminal and run:

```bash
sudo pkill sentinel
```

or:

```bash
sudo killall sentinel
```

---

### Option 3: Systemd Service Command (If running as a background Linux service)

If you installed and enabled `sentinel` as an Ubuntu system service:

```bash
sudo systemctl stop sentinel
```