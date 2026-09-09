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

# 1. High-Speed Syslog Log Flood (100,000 logs)
echo -e "\n${YELLOW}[Stage 1] Launching High-Volume Syslog Burst (50,000 events)...${NC}"
sudo docker exec -d sim-ubuntu-web-cluster sh -c "
  for i in \$(seq 1 50000); do
    logger \"AUDITD_SECURITY_EVENT #\$i: Failed password for root from 172.30.0.250 port \$((1000 + i)) ssh2\"
  done
"
echo -e "${GREEN}Syslog burst stream launched!${NC}"

# 2. Parallel Attacker Node 1: Nmap Port Scan & SYN Flood
echo -e "\n${RED}[Stage 2] Attacker Node 1 (172.30.0.250): SYN Packet Scan & SYN Flood...${NC}"
sudo docker exec -d sim-attacker-ddos nmap -sS -p 1-10000 -T5 ${TARGET_IP}
sudo docker exec -d sim-attacker-ddos hping3 --syn -p 80 --faster -c 20000 ${TARGET_IP} || true

# 3. Parallel Attacker Node 2: Industrial SCADA PLC Overrides (Modbus TCP Port 502 & DNP3 Port 20000)
echo -e "\n${RED}[Stage 3] Attacker Node 2 (172.30.0.251): Industrial SCADA Sabotage Attack...${NC}"
sudo docker exec -d sim-attacker-scada sh -c "
  for i in \$(seq 1 5000); do
    echo 'MALICIOUS_UNAUTHORIZED_MODBUS_COIL_WRITE' | nc -w 1 ${TARGET_IP} 502
    echo 'UNAUTHORIZED_DNP3_SUBSTATION_OVERRIDE' | nc -w 1 ${TARGET_IP} 20000
  done
"

# 4. Parallel Attacker Node 3: SSH/RDP Hydra Brute-Force Attack
echo -e "\n${RED}[Stage 4] Attacker Node 3 (172.30.0.252): Brute-Force Exploit Stream...${NC}"
sudo docker exec -d sim-attacker-bruteforce sh -c "
  for i in \$(seq 1 5000); do
    echo 'SSH_BRUTE_FORCE_PAYLOAD_\$i' | nc -w 1 ${TARGET_IP} 22
  done
"

# 5. Monitor Blackbox Sentinel Performance Metrics
echo -e "\n${BLUE}[Stage 5] Querying Blackbox Sentinel Appliance Health & Telemetry...${NC}"
sleep 2

if curl -s http://localhost:8443 | grep -q "ACTIVE"; then
    echo -e "${GREEN}Sentinel REST API Response:${NC}"
    curl -s http://localhost:8443 | jq . || curl -s http://localhost:8443
    echo ""
else
    echo -e "${YELLOW}Notice: Sentinel daemon is not running. Start it in another terminal: 'sudo ./build/sentinel'${NC}"
fi

echo -e "\n${GREEN}=================================================================${NC}"
echo -e "${GREEN} Massive Stress Test Triggered! Check http://localhost:8443      ${NC}"
echo -e "${GREEN}=================================================================${NC}"