class ThreatConsoleController {
    constructor() {
        this.consoleEl = document.getElementById('live-threat-console');
        this.autoScrollEl = document.getElementById('chk-autoscroll');
        this.btnClear = document.getElementById('btn-clear-console');

        this.btnClear.addEventListener('click', () => {
            this.consoleEl.innerHTML = '';
        });
    }

    appendLog(event) {
        const line = document.createElement('div');
        const levelClass = event.level === 'CRITICAL' ? 'log-critical' : (event.level === 'HIGH' ? 'log-high' : 'log-info');
        const tagClass = event.level === 'CRITICAL' ? 'tag-critical' : (event.level === 'HIGH' ? 'tag-high' : 'tag-info');

        line.className = `log-line ${levelClass}`;
        line.innerHTML = `
            <span class="log-ts">[${new Date().toLocaleTimeString()}]</span>
            <span class="log-tag ${tagClass}">${event.level}</span>
            <span class="log-msg">IP: ${event.ip} | Score: ${event.score} | Action: ${event.action} (${event.desc})</span>
        `;

        this.consoleEl.appendChild(line);

        if (this.autoScrollEl.checked) {
            this.consoleEl.scrollTop = this.consoleEl.scrollHeight;
        }
    }
}

window.threatConsole = new ThreatConsoleController();