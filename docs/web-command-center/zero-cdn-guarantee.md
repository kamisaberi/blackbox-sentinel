# The Zero-CDN Invariant: Absolute Network Isolation

Commercial enterprise security web dashboards frequently rely on Content Delivery Networks (CDNs) to fetch frontend dependencies: Google Fonts, Bootstrap CSS, FontAwesome icons, or Cloudflare-hosted React/Vue runtimes.

In air-gapped industrial, healthcare, and defense networks, external requests cause loading timeouts, broken user interfaces, and severe regulatory violations. `blackbox-sentinel` enforces an **absolute Zero-CDN Guarantee**.

---

## 1. Zero External Asset Dependencies

```text
CONVENTIONAL WEB CONSOLE (Vulnerable to Outages & Data Leakage):
 [ Browser ] ────(Failed HTTP GET)────► [ fonts.googleapis.com ] ──► (Blocked)
 [ Browser ] ────(Failed HTTP GET)────► [ cdn.jsdelivr.net     ] ──► (Blocked)
 Result: 30-Second Browser Timeout, Broken CSS, Script Execution Errors

--------------------------------------------------------------------------------

BLACKBOX-SENTINEL EMBEDDED CONSOLE (100% Air-Gapped Compliant):
 [ Browser ] ────(Single HTTPS Request)────► [ sentinel:8443 ]
                                                    │
                                                    ▼
                     [ Serves Self-Contained In-Memory Asset Bundle ]
                     • Embedded Pure CSS (Custom Obsidian/Cyan Theme)
                     • Embedded Vanilla JavaScript (No External Frameworks)
                     • Inline SVG Vector Icons & HTML5 Canvas Rendering
                     • ZERO External Network Calls ($0.00 Egress)
```

---

## 2. In-Memory Asset Compilation (`EmbeddedWebAssets.hpp`)

Static HTML, CSS, JavaScript, and SVG assets are minified, compressed with gzip, and converted into binary C++ byte arrays during compilation using a custom CMake tool (`bin2c`):

```cpp
#pragma once

#include <cstdint>
#include <span>

namespace sentinel::web {

// Statically compiled in-memory compressed assets
extern const uint8_t INDEX_HTML_GZ[];
extern const size_t INDEX_HTML_GZ_LEN;

extern const uint8_t APP_JS_GZ[];
extern const size_t APP_JS_GZ_LEN;

class AssetManager {
public:
    static std::span<const uint8_t> get_asset(std::string_view path, std::string_view& out_mime_type) noexcept {
        if (path == "/" || path == "/index.html") {
            out_mime_type = "text/html; charset=utf-8";
            return {INDEX_HTML_GZ, INDEX_HTML_GZ_LEN};
        }
        if (path == "/app.js") {
            out_mime_type = "application/javascript; charset=utf-8";
            return {APP_JS_GZ, APP_JS_GZ_LEN};
        }
        out_mime_type = "text/plain";
        return {};
    }
};

} // namespace sentinel::web
```

---

## 3. Auditing the Zero-CDN Guarantee

Verify that the web interface makes zero outbound requests by inspecting browser network calls with `curl`:

```bash
# Verify headers and payload
curl -k -I https://localhost:8443/
```

Check the response body to confirm all fonts, stylesheets, and scripts are served with internal relative paths (`href="/style.css"`, `src="/app.js"`), with zero external `http://` or `https://` references.

