# Blackbox Sentinel Community Threat Rules

This directory contains production-grade, zero-downtime threat detection and active mitigation rules for **Blackbox Sentinel**.

---

## Directory Overview

* **`lua/`**: Dynamic, hot-reloadable threat heuristics executed via **LuaJIT 2.1 C-FFI**.
  * Evaluated in **$< 450\,\text{ns}$** per frame.
  * Deployed in **$< 2\,\text{ms}$** with zero daemon restart or packet loss via Linux `inotify`.
  * Safe sandboxing: `os`, `io`, and raw file I/O are disabled.

---

## Included Community Rules

| Rule File | Target Threat | Target Port | Mitigation Action |
| :--- | :--- | :--- | :--- |
| `100_threat_log4j_jndi.lua` | Sliding window `${jndi:` scanner | All (0) | `SENTINEL_VERDICT_KERNEL_DROP` |
| `200_threat_modbus_burst.lua` | Actuator write oscillation ($> 5/\text{sec}$) | 502 (Modbus) | `SENTINEL_VERDICT_KERNEL_DROP` |
| `300_threat_http_zeroday.lua` | Hostile exploit probe header filter | 80 (HTTP) | `SENTINEL_VERDICT_KERNEL_DROP` |

---

## How to Author a Custom Lua Rule

Create a `.lua` file exporting a global `Rule` table:

```lua
local ffi = ffi or require("ffi")

Rule = {
    id   = 6001,               -- Unique rule ID
    name = "MY_CUSTOM_RULE",   -- Canonical rule identifier
    port = 502                 -- Target port (0 for all ports)
}

function Rule.inspect(pkt)
    -- pkt.data   : Raw pointer (const uint8_t*)
    -- pkt.length : Frame size (size_t cdata, use tonumber(pkt.length))
    
    local len = tonumber(pkt.length)
    if not len or len < 8 then return 0 end

    -- Return Verdict:
    -- 0 = PASS
    -- 2 = ALERT
    -- 3 = KERNEL_DROP (Issues in-kernel eBPF drop in < 0.84 us)
    return 0
end