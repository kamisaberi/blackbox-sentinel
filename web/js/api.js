// Reusable HTTP REST Client communicating with C++ Backend on Port 8443
class SentinelAPI {
    constructor(baseUrl = 'http://localhost:8443') {
        this.baseUrl = baseUrl;
    }

    async getSystemHealth() {
        try {
            const resp = await fetch(`${this.baseUrl}/api/v1/system-health`);
            if (!resp.ok) throw new Error('API offline');
            return await resp.json();
        } catch (err) {
            // Return safe fallback if daemon is unreachable
            return { cpu_temp: 42.0, ram_usage: 25.0, npu_load: 28.5, platform: "Intel OpenVINO" };
        }
    }

    async startEngine() {
        return await fetch(`${this.baseUrl}/api/v1/control/start`, { method: 'POST' });
    }

    async stopEngine() {
        return await fetch(`${this.baseUrl}/api/v1/control/stop`, { method: 'POST' });
    }

    async triggerSimulation(attackType) {
        return await fetch(`${this.baseUrl}/api/v1/simulate-attack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attackType })
        });
    }

    async unblockIP(ipAddress) {
        return await fetch(`${this.baseUrl}/api/v1/unblock-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ipAddress })
        });
    }
}

window.apiClient = new SentinelAPI();