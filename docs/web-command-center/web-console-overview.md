# Web Command Center Architecture (Port 8443 HTTPS)

`blackbox-sentinel` embeds a lightweight, high-performance C++20 HTTPS server serving an air-gapped Single-Page Application (SPA) on port **8443**. It allows system administrators and plant engineers to inspect real-time telemetry, manage active kernel drops, and audit detections without external network dependencies.

---

## 1. Embedded Server Architecture

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Web Browser (Operator Workstation / Engineering Laptop)     │
 └──────────────────────────────▲──────────────────────────────┘
                                │ HTTPS TLS 1.3 (Port 8443)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ blackbox-sentinel: Embedded HTTPS Server Core               │
 │  - Native C++20 Non-Blocking HTTP/1.1 & HTTP/2 Engine       │
 │  - TLS 1.3 Termination (OpenSSL EVP Session Management)     │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Static Assets Router  ▼ REST API Dispatcher   ▼ Real-Time SSE Stream
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Serves       │        │ Handles      │        │ Pushes 10 Hz │
 │ In-Memory    │        │ JSON APIs    │        │ Telemetry to │
 │ Pre-Compiled │        │ (/api/v1/...)│        │ Web Client   │
 │ HTML5 Bundle │        │              │        │ (/stream)    │
 └──────────────┘        └──────┬───────┘        └──────────────┘
                                │ In-Process State Access
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Subsystem States, eBPF Maps, and AI Diagnostics             │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Core API Endpoints

| HTTP Method | Route Path | Description | Access Role |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Serves the compressed HTML5 SPA bundle directly from RAM. | Anonymous |
| `POST` | `/api/v1/auth/login` | Validates admin credentials; returns a scoped JWT bearer token. | Anonymous |
| `GET` | `/api/v1/telemetry/live` | Returns snapshot of CPU, RAM, NPU temp, and ring throughput. | Admin / Operator |
| `GET` | `/api/v1/telemetry/stream`| Server-Sent Events (SSE) stream pushing updates at $10\text{ Hz}$. | Admin / Operator |
| `GET` | `/api/v1/drops/active` | Dumps current contents of the in-kernel `blocked_ip_map`. | Admin / Operator |
| `POST` | `/api/v1/drops/unblock` | Removes an IP from `blocked_ip_map` immediately via BPF syscall. | Admin |
| `GET` | `/api/v1/xai/attributions` | Returns top-3 physical feature deviations for active alerts. | Admin / Operator |
| `POST` | `/api/v1/control/reload` | Triggers a zero-downtime hot-reload of AI model weights. | Admin |

---

## 3. Configuration in `sentinel.yaml`

```yaml
web_console:
  enabled: true
  bind_address: "0.0.0.0"
  port: 8443
  max_concurrent_connections: 64
  session_timeout_minutes: 30
  ssl_certificate: "/etc/sentinel/certs/server.crt"
  ssl_private_key: "/etc/sentinel/certs/server.key"
  rate_limit:
    max_requests_per_second: 100
```

