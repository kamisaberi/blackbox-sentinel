#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}      Blackbox Sentinel Appliance Launcher           ${NC}"
echo -e "${GREEN}=====================================================${NC}"

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Launching Sentinel requires sudo privileges (for eBPF/XDP & raw sockets).${NC}"
  echo -e "Usage: sudo ./scripts/launch_sentinel.sh"
  exit 1
fi

# Check if Sentinel is already running
if pgrep -x "sentinel" > /dev/null; then
    echo -e "${YELLOW}Warning: Blackbox Sentinel daemon is already running!${NC}"
    echo -e "To stop it first, run: sudo ./scripts/stop_sentinel.sh"
    exit 1
fi

# Update shared library cache
ldconfig

# Locate Sentinel binary
SENTINEL_BIN=""
if [ -f "./build/sentinel" ]; then
    SENTINEL_BIN="./build/sentinel"
elif [ -f "/usr/local/bin/sentinel" ]; then
    SENTINEL_BIN="/usr/local/bin/sentinel"
else
    echo -e "${RED}Error: Could not find 'sentinel' binary! Please compile first: 'cd build && cmake .. && make'${NC}"
    exit 1
fi

# Automatically start Docker Simulation Testbed if not active
if command -v docker &> /dev/null; then
    if ! docker ps | grep -q "sim-ubuntu-server"; then
        echo -e "${YELLOW}[Info] Simulation containers are not active. Starting Docker simulation testbed...${NC}"
        if [ -f "docker-compose.massive.yml" ]; then
            docker-compose -f docker-compose.massive.yml up -d
        elif [ -f "simulation/docker-compose.sim.yml" ]; then
            docker-compose -f simulation/docker-compose.sim.yml up -d
        fi
    fi
fi

echo -e "\n${GREEN}[Launch] Starting Blackbox Sentinel Daemon...${NC}"
echo -e "${GREEN}[Info] Web Command Center active at: http://localhost:8443${NC}\n"

# Launch Sentinel
exec ${SENTINEL_BIN}