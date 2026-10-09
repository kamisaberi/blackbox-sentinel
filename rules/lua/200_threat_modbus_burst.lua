-- ============================================================================
-- Blackbox Sentinel Community Rule
-- Threat Vector : Cyber-Physical / Rapid Actuator Oscillation Attack
-- Target Ports  : TCP 502 (Modbus TCP)
-- Latency SLA   : < 450 nanoseconds
-- ============================================================================

local ffi = ffi or require("ffi")

Rule = {
    id   = 5002,
    name = "CPS_MODBUS_WRITE_BURST_RATE_LIMIT",
    port = 502
}

local write_count = 0
local window_start_ns = 0
local MAX_WRITES_PER_SEC = 5

function Rule.inspect(pkt)
    if not pkt or not pkt.data then return 0 end
    local len = tonumber(pkt.length)
    if not len or len < 8 then return 0 end

    -- Modbus TCP Protocol ID must be 0x0000
    if pkt.data[2] ~= 0 or pkt.data[3] ~= 0 then return 0 end

    -- Byte 7 is the Modbus Function Code
    local fc = pkt.data[7]
    -- FC 05 (Write Single Coil), FC 06 (Write Single Register), FC 16 (Write Multiple Registers)
    if fc == 5 or fc == 6 or fc == 16 then
        local now = tonumber(pkt.timestamp_ns)
        if window_start_ns == 0 or (now - window_start_ns) > 1000000000 then
            window_start_ns = now
            write_count = 1
        else
            write_count = write_count + 1
            if write_count > MAX_WRITES_PER_SEC then
                return 3 -- SENTINEL_VERDICT_KERNEL_DROP
            end
        end
    end
    return 0 -- PASS
end
