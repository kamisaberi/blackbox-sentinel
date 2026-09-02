#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Gateway IP connecting containers to the host where Sentinel runs
TARGET_IP="172.28.0.1"

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN} Blackbox Sentinel Multi-Device Simulation Testbed   ${NC}"
echo -e "${GREEN}=====================================================${NC}"

# 0. Ensure attack tools are installed in sim-attacker container
echo -e "\n${YELLOW}[Setup] Verifying attack tools in sim-attacker container...${NC}"
sudo docker exec sim-attacker apt-get update -qq
sudo docker exec sim-attacker apt-get install -y -qq nmap netcat-openbsd curl > /dev/null

# 1. Forward a log from simulated Linux client to Sentinel (172.28.0.1:514)
echo -e "\n${YELLOW}[Step 1] Forwarding test Syslog from simulated Ubuntu client to ${TARGET_IP}:514...${NC}"
sudo docker exec sim-ubuntu-server logger "AUDITD_ALERT: Failed password for root from 172.28.0.250 port 54321 ssh2" || true
echo -e "${GREEN}Syslog forwarded to ${TARGET_IP}:514!${NC}"

# 2. Launch simulated port scan attack targeting Blackbox Sentinel (172.28.0.1)
echo -e "\n${RED}[Step 2] Launching Nmap Port Scan attack targeting Sentinel (${TARGET_IP})...${NC}"
sudo docker exec sim-attacker nmap -sS -p 22,80,443,502,8443 ${TARGET_IP} || true

# 3. Launch simulated unauthorized Modbus PLC Write attack to Sentinel (172.28.0.1:502)
echo -e "\n${RED}[Step 3] Launching unauthorized Modbus PLC Write attack to ${TARGET_IP}:502...${NC}"
sudo docker exec sim-attacker sh -c "echo 'MALICIOUS_MODBUS_WRITE_COMMAND' | nc -w 1 ${TARGET_IP} 502" || true

# 4. Check Sentinel REST API
echo -e "\n${GREEN}[Step 4] Querying Blackbox Sentinel REST API (http://localhost:8443)...${NC}"
if curl -s http://localhost:8443 | grep -q "ACTIVE"; then
    echo -e "${GREEN}Sentinel Appliance REST API Responding: ACTIVE!${NC}"
else
    echo -e "${YELLOW}Notice: Sentinel daemon is not running. Start it in Terminal 1: 'sudo ./build/sentinel'${NC}"
fi

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN} Simulation Complete! Open http://localhost:8443 in   ${NC}"
echo -e "${GREEN} your browser to view the live threat feed.          ${NC}"
echo -e "${GREEN}=====================================================${NC}"