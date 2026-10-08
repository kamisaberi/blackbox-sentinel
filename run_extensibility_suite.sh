#!/usr/bin/env bash
set -e

echo "============================================================"
echo "    SENTINEL EXTENSIBILITY AUTOMATED BUILD & TEST SUITE    "
echo "============================================================"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# 1. Provision target directories
echo "[+] Step 1: Provisioning /etc/sentinel directories..."
sudo mkdir -p /etc/sentinel/rules.d
sudo mkdir -p /etc/sentinel/plugins.d
sudo chown -R "$USER:$USER" /etc/sentinel

# 2. Write the fixed Log4j rule with tonumber()
echo "[+] Step 2: Writing fixed Log4j Lua rule..."
cat << 'LUA' > /etc/sentinel/rules.d/100_threat_log4j_jndi.lua
local ffi = ffi or require("ffi")

Rule = {
    id   = 5001,
    name = "EXPLOIT_LOG4J_JNDI_INJECTION",
    port = 0
}

local function contains_jndi(data, raw_len)
    local len = tonumber(raw_len)
    if not len or len < 8 then return false end
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
LUA

# 3. Write the fixed Modbus Rate Clamp rule with tonumber()
echo "[+] Step 3: Writing fixed Modbus burst Lua rule..."
cat << 'LUA' > /etc/sentinel/rules.d/200_threat_modbus_burst.lua
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

    if pkt.data[2] ~= 0 or pkt.data[3] ~= 0 then return 0 end

    local fc = pkt.data[7]
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
LUA

# 4. Clean up any leftover temporary canary rules
rm -f /etc/sentinel/rules.d/300_threat_test_canary.lua

# 5. Compile the Native C++20 Modbus Guard Plugin
echo "[+] Step 4: Compiling native reference plugin (sentinel_modbus_guard.so)..."
cd examples/plugins/native_modbus_guard
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"
cp -f sentinel_modbus_guard.so /etc/sentinel/plugins.d/
cd "$PROJECT_ROOT"

# 6. Compile the Test Executable (with -Wno-unused-result)
echo "[+] Step 5: Compiling test_extensibility test runner..."
g++ -std=c++20 -O3 -march=native -Wno-unused-result \
    examples/05_test_extensibility_engine.cpp \
    src/sdk/NativePluginLoader.cpp \
    src/sdk/LuaHotReloadEngine.cpp \
    src/sdk/PluginSupervisor.cpp \
    -Iinclude \
    -Isrc \
    $(pkg-config --cflags --libs luajit) \
    -lcrypto -ldl -lpthread \
    -o test_extensibility

echo "[+] Step 6: Running test suite..."
echo "------------------------------------------------------------"
sudo ./test_extensibility
echo "------------------------------------------------------------"
echo "[SUCCESS] Extensibility Subsystem is fully operational!"

