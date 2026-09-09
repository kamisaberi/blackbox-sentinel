Here is the complete step-by-step guide to launch the **12-container massive simulation environment** and execute the **massive stress test** on your machine.

---

### Prerequisites Check

Before starting, make sure you are in the `blackbox-sentinel` project root directory:

```bash
cd /home/kami/blackbox-sentinel
```

Ensure the stress script has execution permissions:

```bash
chmod +x scripts/massive_stress_test.sh scripts/attack_console.py
```

---

### Step 1: Spin Up the 12-Container Simulation Network

Run Docker Compose using the massive configuration file:

```bash
sudo docker compose -f docker-compose.massive.yml up -d
```
*(If your system uses the older standalone binary, use `sudo docker-compose -f docker-compose.massive.yml up -d` instead).*

#### Verify Containers Are Running:
```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

You should see all 11 simulated enterprise and attacker containers running:
* `sim-ubuntu-web-cluster`
* `sim-windows-dc`
* `sim-modbus-plc-1`
* `sim-modbus-plc-2`
* `sim-dnp3-substation`
* `sim-rtsp-camera-1`
* `sim-rtsp-camera-2`
* `sim-iot-smart-meters`
* `sim-attacker-ddos`
* `sim-attacker-scada`
* `sim-attacker-bruteforce`

---

### Step 2: Pre-Install Attack Utilities inside Attacker Nodes

To ensure the attack nodes do not fail with "command not found" errors during the flood test, run this quick preparation command once:

```bash
sudo docker exec sim-attacker-ddos apt-get update -qq && sudo docker exec sim-attacker-ddos apt-get install -y -qq nmap hping3 curl netcat-openbsd > /dev/null
sudo docker exec sim-attacker-scada apt-get update -qq && sudo docker exec sim-attacker-scada apt-get install -y -qq netcat-openbsd > /dev/null
sudo docker exec sim-attacker-bruteforce apt-get update -qq && sudo docker exec sim-attacker-bruteforce apt-get install -y -qq netcat-openbsd > /dev/null
```

---

### Step 3: Start the Blackbox Sentinel Daemon (Terminal 1)

Open **Terminal 1** and start the Sentinel appliance daemon:

```bash
cd /home/kami/blackbox-sentinel
sudo ./build/sentinel
```

#### Expected Terminal 1 Output:
```text
==========================================================
  BLACKBOX SENTINEL™ Cyber-Physical Threat Defense Node   
  Powered by libblackbox.so & libxinfer.so                
==========================================================
[Blackbox Sentinel] Initializing libblackbox.so security engine...
[libblackbox.so] Engine processing loop started.
[Sentinel Server] Web Command Center & REST API active at http://localhost:8443
[Blackbox Sentinel] Web Command Center live at: http://localhost:8443
```

---

### Step 4: Run the Massive Stress Test (Terminal 2)

Open **Terminal 2** and execute the automated high-throughput stress test:

```bash
cd /home/kami/blackbox-sentinel
sudo ./scripts/massive_stress_test.sh
```

#### What the Script Executes:
1. **Stage 1 (Syslog Flood):** Injects 50,000 Auditd/Syslog authentication failure events from `sim-ubuntu-web-cluster` into port 514.
2. **Stage 2 (Network Flood & Scan):** Runs high-concurrency Nmap SYN scans across 10,000 ports alongside high-speed `hping3` TCP SYN packet floods from `sim-attacker-ddos` (172.30.0.250).
3. **Stage 3 (SCADA Sabotage):** Injects 5,000 unauthorized Modbus TCP coil overrides (port 502) and DNP3 commands (port 20000) from `sim-attacker-scada` (172.30.0.251).
4. **Stage 4 (Brute-Force Stream):** Streams 5,000 rapid authentication exploit payloads from `sim-attacker-bruteforce` (172.30.0.252).
5. **Stage 5 (Telemetry Query):** Automatically polls the REST API on `http://localhost:8443` to retrieve real-time CPU, RAM, and blocked IP statistics.

---

### Step 5: (Alternative) Run the Interactive Attack Controller

If you prefer to manually start, stop, and switch attack types in real time rather than running a one-shot script, launch the interactive Python console in Terminal 2 instead:

```bash
cd /home/kami/blackbox-sentinel
sudo python3 scripts/attack_console.py
```

* Press `1` to toggle Nmap port scans ON/OFF.
* Press `2` to toggle SCADA Modbus PLC sabotage ON/OFF.
* Press `3` to toggle SSH brute-forcing ON/OFF.
* Press `4` to toggle high-volume SYN floods ON/OFF.
* Press `6` to trigger all attacks simultaneously.
* Press `7` to immediately stop all attacks and return the environment to idle.

---

### Step 6: Monitor Results in Web Command Center

While the stress test or attack console is running, open your browser to:

```text
http://localhost:8443
```

Observe in real time:
- **Metrics Gauges:** Live CPU utilization, RAM usage, and NPU/GPU load processing the event stream.
- **Live Threat Console:** Real-time log streamer rendering anomaly alerts with microsecond-level timestamps.
- **Active eBPF Table:** The attacker IPs (`172.30.0.250`, `172.30.0.251`, and `172.30.0.252`) listed under kernel XDP drop with instant `[1-CLICK UNBLOCK]` buttons available.

---

### Step 7: Clean Shutdown When Finished

When you are finished testing:

1. **Stop the Sentinel Daemon in Terminal 1:**
   Press `Ctrl + C` (or run `sudo ./scripts/stop_sentinel.sh` in another terminal).

2. **Shut Down the 12-Container Simulation Network:**
   ```bash
   sudo docker compose -f docker-compose.massive.yml down
   ```