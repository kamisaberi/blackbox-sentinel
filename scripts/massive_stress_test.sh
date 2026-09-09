#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_IP="172.30.0.1"

echo -e "${GREEN}=================================================================${NC}"
echo -e "${GREEN}   Blackbox Sentinel Massive Stress Test (i9-14900K / 192GB RAM)  ${NC}"
echo -e "${GREEN}=================================================================${NC}"

# 1. High-Speed Syslog Log Flood (50,000 logs)
echo -e "\n${YELLOW}[Stage 1] Launching High-Volume Syslog Burst (50,000 events)...${NC}"
sudo docker exec -d sim-ubuntu-web-cluster sh -c "
  for i in \$(seq 1 50000); do
    logger \"AUDITD_SECURITY_EVENT #\$i: Failed password for root from 172.30.0.250 port \$((1000 + i)) ssh2\"
  done
"
echo -e "${GREEN}Syslog burst stream dispatched!${NC}"

# 2. Parallel Attacker Node 1: Nmap Port Scan & SYN Flood
echo -e "\n${RED}[Stage 2] Attacker Node 1 (172.30.0.250): Port Scan & 20k SYN Packet Flood...${NC}"
sudo docker exec -d sim-attacker-ddos nmap -sS -p 1-1000 -T5 ${TARGET_IP}
sudo docker exec -d sim-attacker-ddos hping3 --syn -p 80 --faster -c 20000 ${TARGET_IP}

# 3. Parallel Attacker Node 2: Industrial SCADA PLC Overrides (Non-blocking batches)
echo -e "\n${RED}[Stage 3] Attacker Node 2 (172.30.0.251): SCADA Modbus & DNP3 Sabotage Bursts...${NC}"
sudo docker exec -d sim-attacker-scada sh -c "
  for batch in \$(seq 1 50); do
    for i in \$(seq 1 20); do
      echo 'MALICIOUS_MODBUS_COIL_WRITE' | nc -w 1 -q 0 ${TARGET_IP} 502 &
      echo 'UNAUTHORIZED_DNP3_OVERRIDE'   | nc -w 1 -q 0 ${TARGET_IP} 20000 &
    done
    wait
  done
"

# 4. Parallel Attacker Node 3: SSH Brute-Force Exploit Stream (Non-blocking batches)
echo -e "\n${RED}[Stage 4] Attacker Node 3 (172.30.0.252): Rapid Authentication Exploit Bursts...${NC}"
sudo docker exec -d sim-attacker-bruteforce sh -c "
  for batch in \$(seq 1 50); do
    for i in \$(seq 1 20); do
      echo 'SSH_BRUTE_FORCE_PAYLOAD' | nc -w 1 -q 0 ${TARGET_IP} 22 &
    done
    wait
  done
"

# 5. Monitor Blackbox Sentinel Performance Metrics via REST API
echo -e "\n${BLUE}[Stage 5] Querying Blackbox Sentinel Appliance Health & Telemetry...${NC}"
sleep 2

if curl -s http://localhost:8443/api/v1/system-health | grep -q "status"; then
    echo -e "${GREEN}Sentinel REST API Response:${NC}"
    if command -v jq &> /dev/null; then
        curl -s http://localhost:8443/api/v1/system-health | jq .
    else
        curl -s http://localhost:8443/api/v1/system-health
    fi
    echo ""
else
    echo -e "${YELLOW}Notice: Sentinel daemon is not running on port 8443 yet. Start it in Terminal 1: 'sudo ./build/sentinel'${NC}"
fi

echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN} Massive Stress Test Triggered! Check http://localhost:8443      ${NC}"
echo -e "${GREEN}=================================================================${NC}"