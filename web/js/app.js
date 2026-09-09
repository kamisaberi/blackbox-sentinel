document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel™ Web Command Center Initialized.");

    const jsonDisplay = document.getElementById('json-threats-display');
    const btnCopyJson = document.getElementById('btn-copy-json');

    // Function to fetch and pretty-print JSON threats
    async function updateJsonThreats() {
        if (!jsonDisplay) return;
        try {
            const resp = await fetch(`/api/v1/threats?t=${Date.now()}`, { cache: 'no-store' });
            if (resp.ok) {
                const data = await resp.json();
                // Pretty-print JSON with 2-space indentation
                jsonDisplay.innerText = JSON.stringify(data, null, 2);
            }
        } catch (err) {
            console.log("Fetching JSON threats...");
        }
    }

    // Update JSON viewer every 2 seconds
    updateJsonThreats();
    setInterval(updateJsonThreats, 2000);

    // Copy JSON to clipboard
    if (btnCopyJson) {
        btnCopyJson.addEventListener('click', () => {
            navigator.clipboard.writeText(jsonDisplay.innerText);
            btnCopyJson.innerText = "COPIED!";
            setTimeout(() => { btnCopyJson.innerText = "COPY JSON"; }, 1500);
        });
    }

    // Connect WebSocket live event listener
    window.wsClient.onMessage((eventData) => {
        window.threatConsole.appendLog(eventData);
        if (eventData.level === 'CRITICAL' && eventData.ip) {
            window.ebpfTable.addBlockedRow(eventData.ip, eventData.desc);
        }
    });
});