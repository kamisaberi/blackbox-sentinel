-- ============================================================================
-- Blackbox Sentinel Community Rule
-- Threat Vector : Remote Code Execution (RCE) / Log4j JNDI Injection
-- Target Ports  : All (Port 0 = inspect all traffic)
-- Latency SLA   : < 450 nanoseconds
-- ============================================================================

local ffi = ffi or require("ffi")

Rule = {
    id   = 5001,
    name = "EXPLOIT_LOG4J_JNDI_INJECTION",
    port = 0
}

local function contains_jndi(data, raw_len)
    local len = tonumber(raw_len)
    if not len or len < 8 then return false end
    
    -- Sliding window byte scan for "${jndi:" pattern without memory allocations
    for i = 0, len - 7 do
        if data[i] == 0x24 and data[i+1] == 0x7B then -- "${"
            if data[i+2] == 0x6A and data[i+3] == 0x6E and data[i+4] == 0x64 and data[i+5] == 0x69 and data[i+6] == 0x3A then
                return true
            end
        end
    end
    return false
end

function Rule.inspect(pkt)
    if not pkt or not pkt.data then return 0 end
    if contains_jndi(pkt.data, pkt.length) then
        return 3 -- SENTINEL_VERDICT_KERNEL_DROP
    end
    return 0 -- PASS
end
