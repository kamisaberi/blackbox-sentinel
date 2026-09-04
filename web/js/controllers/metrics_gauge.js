document.addEventListener('DOMContentLoaded', () => {
    const tempEl = document.getElementById('metric-cpu-temp');
    const ramEl = document.getElementById('metric-ram-usage');
    const npuEl = document.getElementById('metric-npu-load');

    const barCpu = document.getElementById('progress-cpu');
    const barRam = document.getElementById('progress-ram');
    const barNpu = document.getElementById('progress-npu');

    setInterval(async () => {
        const metrics = await window.apiClient.getSystemHealth();
        tempEl.innerText = metrics.cpu_temp.toFixed(1);
        ramEl.innerText = metrics.ram_usage.toFixed(1);
        npuEl.innerText = metrics.npu_load.toFixed(1);

        barCpu.style.width = `${Math.min(100, metrics.cpu_temp)}%`;
        barRam.style.width = `${Math.min(100, metrics.ram_usage)}%`;
        barNpu.style.width = `${Math.min(100, metrics.npu_load)}%`;
    }, 2000);
});