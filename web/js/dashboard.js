document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel Command Center Connected.");

    const logConsole = document.getElementById('log-console');

    setInterval(async () => {
        try {
            const response = await fetch('http://localhost:8443');
            if (response.ok) {
                const data = await response.json();
                
                // 1. Update Hardware Metrics Gauges
                document.getElementById('cpu-temp').innerText = data.cpu_temp.toFixed(1) + ' °C';
                document.getElementById('ram-usage').innerText = data.ram_usage.toFixed(1) + ' %';
                document.getElementById('npu-load').innerText = data.npu_load.toFixed(1) + ' %';

                // 2. Render Live Threat Event Logs into Console
                if (data.threats && data.threats.length > 0) {
                    logConsole.innerHTML = ''; // Clear placeholder text
                    
                    data.threats.forEach(threat => {
                        const p = document.createElement('p');
                        p.className = (threat.level === 'CRITICAL') ? 'critical' : 'info';
                        
                        const timeStr = new Date().toLocaleTimeString();
                        p.innerText = `[${timeStr}] [${threat.level}] IP: ${threat.ip} | Anomaly Score: ${threat.score} | Action: ${threat.action} (${threat.desc})`;
                        
                        logConsole.appendChild(p);
                    });
                }
            }
        } catch (err) {
            console.log("Fetching local metrics...");
        }
    }, 2000);
});