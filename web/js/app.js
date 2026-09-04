// Master Application Coordinator
document.addEventListener('DOMContentLoaded', () => {
    console.log("Blackbox Sentinel™ Web Command Center Initialized.");

    // Connect WebSocket live event listener
    window.wsClient.onMessage((eventData) => {
        window.threatConsole.appendLog(eventData);
        if (eventData.level === 'CRITICAL' && eventData.ip) {
            window.ebpfTable.addBlockedRow(eventData.ip, eventData.desc);
        }
    });
});