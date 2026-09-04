document.addEventListener('DOMContentLoaded', () => {
    const bindBtn = (id, type) => {
        document.getElementById(id).addEventListener('click', () => {
            window.apiClient.triggerSimulation(type);
            // Instant local visual feedback
            if (type === 'nmap') {
                window.threatConsole.appendLog({ level: 'CRITICAL', ip: '172.30.0.250', score: 0.98, action: 'eBPF Kernel Drop', desc: 'Port Scan Flood Blocked' });
                window.ebpfTable.addBlockedRow('172.30.0.250', 'Nmap Port Scan Flood');
            } else if (type === 'modbus') {
                window.threatConsole.appendLog({ level: 'CRITICAL', ip: '172.30.0.251', score: 0.99, action: 'eBPF Kernel Drop', desc: 'Unauthorized SCADA Modbus Write' });
                window.ebpfTable.addBlockedRow('172.30.0.251', 'SCADA PLC Sabotage');
            } else if (type === 'ssh') {
                window.threatConsole.appendLog({ level: 'HIGH', ip: '172.30.0.252', score: 0.88, action: 'Logged', desc: 'SSH Brute Force Burst' });
            }
        });
    };

    bindBtn('sim-btn-nmap', 'nmap');
    bindBtn('sim-btn-modbus', 'modbus');
    bindBtn('sim-btn-ssh', 'ssh');
    bindBtn('sim-btn-multi', 'multi');
    bindBtn('sim-btn-stop', 'stop');
});