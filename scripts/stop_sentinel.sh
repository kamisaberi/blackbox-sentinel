#!/usr/bin/env bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}=====================================================${NC}"
echo -e "${RED}      Blackbox Sentinel Appliance Shutdown           ${NC}"
echo -e "${RED}=====================================================${NC}"

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Warning: Shutdown operations require sudo privileges.${NC}"
fi

# 1. Gracefully terminate Sentinel daemon
if pgrep -x "sentinel" > /dev/null; then
    echo -e "${YELLOW}[Shutdown] Sending graceful SIGINT signal to Blackbox Sentinel daemon...${NC}"
    sudo pkill -2 -x sentinel || sudo killall -2 sentinel
    sleep 1
    echo -e "${GREEN}Blackbox Sentinel daemon stopped successfully!${NC}"
else
    echo -e "${YELLOW}[Info] Blackbox Sentinel daemon is not running.${NC}"
fi

# 2. Stop active attack scripts
echo -e "${YELLOW}[Shutdown] Terminating any active attack console & stress test processes...${NC}"
sudo pkill -f "attack_console.py" 2>/dev/null || true
sudo pkill -f "simulate_attack.sh" 2>/dev/null || true
sudo pkill -f "massive_stress_test.sh" 2>/dev/null || true

# 3. Optional: Stop Docker Simulation Containers
if command -v docker &> /dev/null; then
    if docker ps | grep -q "sim-"; then
        echo -e "\n${YELLOW}Simulation Docker containers are currently active.${NC}"
        read -p "Do you want to stop the Docker simulation containers too? [y/N]: " STOP_DOCKER
        if [[ "$STOP_DOCKER" =~ ^[Yy]$ ]]; then
            echo -e "${RED}[Shutdown] Stopping Docker simulation containers...${NC}"
            if [ -f "docker-compose.massive.yml" ]; then
                sudo docker-compose -f docker-compose.massive.yml down
            elif [ -f "simulation/docker-compose.sim.yml" ]; then
                sudo docker-compose -f simulation/docker-compose.sim.yml down
            fi
            echo -e "${GREEN}Docker simulation containers stopped!${NC}"
        fi
    fi
fi

echo -e "\n${GREEN}=====================================================${NC}"
echo -e "${GREEN} Shutdown Complete.                                 ${NC}"
echo -e "${GREEN}=====================================================${NC}"