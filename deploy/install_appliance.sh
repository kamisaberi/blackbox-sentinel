#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}  Blackbox Sentinel Appliance Turnkey Installer      ${NC}"
echo -e "${GREEN}=====================================================${NC}"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)."
  exit 1
fi

echo "Installing OpenSSL & SQLite Dependencies..."
apt-get update && apt-get install -y libssl-dev libsqlite3-dev build-essential cmake

echo "Compiling Commercial Sentinel Application..."
mkdir -p build && cd build
cmake ..
make -j$(nproc)
make install

echo -e "${GREEN}Blackbox Sentinel Appliance installed successfully!${NC}"