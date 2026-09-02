#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} Blackbox Sentinel Multi-Device Simulation Testbed   ${NC}"
echo -e "${GREEN}=====================================================${NC}"

# 1. Forward a log from simulated Linux client to Sentinel
echo -e "\n${YELLOW}[Step 1] Forwarding test Syslog from simulated Ubuntu client server...${NC}"
docker exec sim-ubuntu-server logger "AUDITD_ALERT: Failed password for root from 172.28.0.250 port 54321 ssh2"
echo -e "${GREEN}Syslog forwarded to port 514!${NC}"

# 2. Launch simulated port scan attack from Attacker Machine
echo -e "\n${RED}[Step 2] Launching Nmap Port Scan attack from Attacker Container (172.28.0.250)...${NC}"
docker exec sim-attacker nmap -sS -p 22,80,443,502 172.28.0.1 || true

# 3. Launch simulated unauthorized Modbus SCADA write attack
echo -e "\n${RED}[Step 3] Launching unauthorized Modbus PLC Write attack to port 502...${NC}"
docker exec sim-attacker sh -c "echo 'MALICIOUS_MODBUS_WRITE_COMMAND' | nc -w 1 172.28.0.1 502" || true

# 4. Check Sentinel REST API for Blocked IP
echo -e "\n${GREEN}[Step 4] Querying Blackbox Sentinel REST API for Blocked IPs...${NC}"
curl -s http://localhost:8443 | grep -q "ACTIVE" && echo -e "${GREEN}Sentinel Appliance REST API Responding: ACTIVE!${NC}"

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN} Simulation Complete! Open http://localhost:8443 in   ${NC}"
echo -e "${GREEN} your browser to view the live threat feed.          ${NC}"
echo -e "${GREEN}=====================================================${NC}"