document.addEventListener('DOMContentLoaded', () => {
    const btnToggle = document.getElementById('btn-engine-toggle');
    const statusDot = document.getElementById('engine-status-dot');
    const statusText = document.getElementById('engine-status-text');
    let isRunning = true;

    btnToggle.addEventListener('click', async () => {
        if (isRunning) {
            btnToggle.innerText = 'START ENGINE';
            btnToggle.className = 'btn btn-sim';
            statusDot.className = 'dot dot-offline';
            statusText.innerText = 'PAUSED';
            isRunning = false;
            await window.apiClient.stopEngine();
        } else {
            btnToggle.innerText = 'STOP ENGINE';
            btnToggle.className = 'btn btn-danger';
            statusDot.className = 'dot dot-online';
            statusText.innerText = 'OPERATIONAL';
            isRunning = true;
            await window.apiClient.startEngine();
        }
    });
});