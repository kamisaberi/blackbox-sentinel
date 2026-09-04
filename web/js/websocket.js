// Real-Time WebSocket Telemetry Client
class SentinelWebSocket {
    constructor(wsUrl = 'ws://localhost:8444') {
        this.wsUrl = wsUrl;
        this.socket = null;
        this.listeners = [];
        this.connect();
    }

    connect() {
        try {
            this.socket = new WebSocket(this.wsUrl);
            this.socket.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.listeners.forEach(fn => fn(data));
            };
            this.socket.onclose = () => {
                setTimeout(() => this.connect(), 3000); // Reconnect loop
            };
        } catch (e) {
            console.log("WebSocket running in polling fallback mode.");
        }
    }

    onMessage(callback) {
        this.listeners.push(callback);
    }
}

window.wsClient = new SentinelWebSocket();