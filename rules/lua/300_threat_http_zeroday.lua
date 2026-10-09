-- ============================================================================
-- Blackbox Sentinel Community Rule
-- Threat Vector : Zero-Day Exploit Header Scanner
-- Target Ports  : TCP 80 / 8080 (Web Application & REST Gateways)
-- ============================================================================

local ffi = ffi or require("ffi")

Rule = {
    id   = 9001,
    name = "FLEET_ZERODAY_HOTFIX",
    port = 80
}

function Rule.inspect(pkt)
    if not pkt or not pkt.data then return 0 end
    local len = tonumber(pkt.length)
    if not len or len < 10 then return 0 end

    for i = 0, len - 16 do
        if pkt.data[i] == 0x58 and pkt.data[i+1] == 0x2D then -- "X-"
            return 3 -- SENTINEL_VERDICT_KERNEL_DROP
        end
    end
    return 0 -- PASS
end
