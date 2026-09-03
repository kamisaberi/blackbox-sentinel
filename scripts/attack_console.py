#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import threading
import urllib.request
import json

# Target Gateway (Host where Blackbox Sentinel listens)
TARGET_IP = "172.30.0.1"

# ANSI Colors
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
CYAN   = "\033[0;36m"
NC     = "\033[0m" # No Color

# Global Active Attack State
attacks_active = {
    "nmap_scan": False,
    "modbus_sabotage": False,
    "ssh_bruteforce": False,
    "syn_flood": False,
    "syslog_burst": False
}

def exec_docker(container, cmd):
    full_cmd = f"sudo docker exec {container} {cmd}"
    return subprocess.run(full_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# =========================================================================
# ATTACK THREAD WORKERS
# =========================================================================

def worker_nmap_scan():
    while attacks_active["nmap_scan"]:
        exec_docker("sim-attacker-ddos", f"nmap -sS -p 22,80,443,502,8443 {TARGET_IP}")
        time.sleep(1)

def worker_modbus_sabotage():
    while attacks_active["modbus_sabotage"]:
        cmd = f"sh -c \"echo 'MALICIOUS_UNAUTHORIZED_MODBUS_WRITE' | nc -w 1 {TARGET_IP} 502\""
        exec_docker("sim-attacker-scada", cmd)
        time.sleep(0.2)

def worker_ssh_bruteforce():
    while attacks_active["ssh_bruteforce"]:
        cmd = f"sh -c \"echo 'SSH_BRUTE_FORCE_ATTACK_VECTOR' | nc -w 1 {TARGET_IP} 22\""
        exec_docker("sim-attacker-bruteforce", cmd)
        time.sleep(0.3)

def worker_syn_flood():
    while attacks_active["syn_flood"]:
        exec_docker("sim-attacker-ddos", f"hping3 --syn -p 80 --faster -c 1000 {TARGET_IP}")
        time.sleep(0.5)

def worker_syslog_burst():
    counter = 0
    while attacks_active["syslog_burst"]:
        counter += 1
        msg = f"AUDITD_HIGH_ANOMALY #{counter}: Failed password for root from 172.30.0.250 port {1000 + counter} ssh2"
        exec_docker("sim-ubuntu-web-cluster", f"logger '{msg}'")
        time.sleep(0.1)

# =========================================================================
# CONTROL ACTIONS
# =========================================================================

def toggle_attack(attack_key, worker_func):
    if attacks_active[attack_key]:
        attacks_active[attack_key] = False
        print(f"{YELLOW}[Attack Console] Stopped {attack_key}{NC}")
    else:
        attacks_active[attack_key] = True
        t = threading.Thread(target=worker_func, daemon=True)
        t.start()
        print(f"{RED}[Attack Console] STARTED {attack_key}!{NC}")

def stop_all_attacks():
    for key in attacks_active:
        attacks_active[key] = False
    print(f"\n{GREEN}[Attack Console] ALL ATTACKS STOPPED! Returning to idle state.{NC}")

def start_all_attacks():
    print(f"\n{RED}[Attack Console] >>> LAUNCHING FULL MULTI-VECTOR ASSAULT <<< {NC}")
    if not attacks_active["nmap_scan"]: toggle_attack("nmap_scan", worker_nmap_scan)
    if not attacks_active["modbus_sabotage"]: toggle_attack("modbus_sabotage", worker_modbus_sabotage)
    if not attacks_active["ssh_bruteforce"]: toggle_attack("ssh_bruteforce", worker_ssh_bruteforce)
    if not attacks_active["syn_flood"]: toggle_attack("syn_flood", worker_syn_flood)
    if not attacks_active["syslog_burst"]: toggle_attack("syslog_burst", worker_syslog_burst)

def check_sentinel_status():
    print(f"\n{BLUE}[Blackbox Sentinel API Query] Checking http://localhost:8443 ...{NC}")
    try:
        req = urllib.request.urlopen("http://localhost:8443", timeout=2)
        if req.getcode() == 200:
            data = json.loads(req.read().decode('utf-8'))
            print(f"{GREEN}Sentinel Status : {data.get('status')}{NC}")
            print(f"CPU Temp        : {data.get('cpu_temp')} °C")
            print(f"RAM Usage       : {data.get('ram_usage')} %")
            print(f"NPU/GPU Load    : {data.get('npu_load')} %")
            print(f"Active Threats  : {len(data.get('threats', []))} logged incidents")
    except Exception as e:
        print(f"{RED}Sentinel REST API is offline or not responding on port 8443.{NC}")

# =========================================================================
# MAIN MENU UI
# =========================================================================

def print_menu():
    os.system('clear')
    print(f"{CYAN}=================================================================${NC}")
    print(f"{CYAN}    BLACKBOX SENTINEL™ Interactive Attack Controller Console      {NC}")
    print(f"{CYAN}=================================================================${NC}")
    print(" Active Attack Vectors Status:")
    
    st_nmap = f"{RED}[ACTIVE]{NC}" if attacks_active["nmap_scan"] else f"{GREEN}[IDLE]{NC}"
    st_scada = f"{RED}[ACTIVE]{NC}" if attacks_active["modbus_sabotage"] else f"{GREEN}[IDLE]{NC}"
    st_ssh = f"{RED}[ACTIVE]{NC}" if attacks_active["ssh_bruteforce"] else f"{GREEN}[IDLE]{NC}"
    st_syn = f"{RED}[ACTIVE]{NC}" if attacks_active["syn_flood"] else f"{GREEN}[IDLE]{NC}"
    st_log = f"{RED}[ACTIVE]{NC}" if attacks_active["syslog_burst"] else f"{GREEN}[IDLE]{NC}"

    print(f"   1. Nmap Port Scan Attack             : {st_nmap}")
    print(f"   2. SCADA Modbus PLC Sabotage         : {st_scada}")
    print(f"   3. SSH Brute Force Exploit           : {st_ssh}")
    print(f"   4. High-Volume SYN / Packet Flood    : {st_syn}")
    print(f"   5. High-Speed Syslog Anomaly Stream  : {st_log}")
    print(f"{CYAN}-----------------------------------------------------------------${NC}")
    print(" Global Controls:")
    print("   6. LAUNCH ALL ATTACKS SIMULTANEOUSLY (Maximum Multi-Vector Load)")
    print("   7. STOP ALL ACTIVE ATTACKS (Emergency Disarm)")
    print("   8. Query Blackbox Sentinel REST API Status")
    print("   9. Exit Console")
    print(f"{CYAN}=================================================================${NC}")

def main():
    while True:
        print_menu()
        try:
            choice = input(f"\n{YELLOW}Select Option [1-9]: {NC}").strip()
            
            if choice == '1':
                toggle_attack("nmap_scan", worker_nmap_scan)
            elif choice == '2':
                toggle_attack("modbus_sabotage", worker_modbus_sabotage)
            elif choice == '3':
                toggle_attack("ssh_bruteforce", worker_ssh_bruteforce)
            elif choice == '4':
                toggle_attack("syn_flood", worker_syn_flood)
            elif choice == '5':
                toggle_attack("syslog_burst", worker_syslog_burst)
            elif choice == '6':
                start_all_attacks()
            elif choice == '7':
                stop_all_attacks()
            elif choice == '8':
                check_sentinel_status()
                input(f"\n{YELLOW}Press Enter to return to menu...{NC}")
            elif choice == '9':
                stop_all_attacks()
                print("\nExiting Attack Console.")
                sys.exit(0)
            
            time.sleep(0.5)
        except (KeyboardInterrupt, SystemExit):
            stop_all_attacks()
            sys.exit(0)

if __name__ == "__main__":
    main()