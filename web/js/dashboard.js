document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel Command Center Connected.");

    // Periodically fetch health metrics from C++ REST API
    setInterval(async () => {
        try {
            const response = await fetch('http://localhost:8443');
            if (response.ok) {
                const data = await response.json();
                document.getElementById('cpu-temp').innerText = data.cpu_temp.toFixed(1) + ' °C';
                document.getElementById('ram-usage').innerText = data.ram_usage.toFixed(1) + ' %';
                document.getElementById('npu-load').innerText = data.npu_load.toFixed(1) + ' %';
            }
        } catch (err) {
            console.log("Fetching local metrics...");
        }
    }, 2000);
});