#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo "    PROVISIONING WASM MICRO-SANDBOX (Wasm3 RUNTIME)        "
echo "============================================================"

# 1. Fetch Wasm3 single-repo source if not present
if [ ! -d "third_party/wasm3" ]; then
    mkdir -p third_party
    git clone --depth 1 https://github.com/wasm3/wasm3.git third_party/wasm3
fi

# 2. Compile static libm3.a
cd third_party/wasm3
mkdir -p build && cd build
cmake .. -DBUILD_WASI=none
make -j"$(nproc)" m3
cd "$PROJECT_ROOT"

# 3. Create Wasm rules directory
sudo mkdir -p /etc/sentinel/wasm.d
sudo chown -R "$USER:$USER" /etc/sentinel

echo "[+] Compiling WasmSandbox and Updated PluginSupervisor..."
g++ -std=c++20 -O3 -march=native -Wno-unused-result \
    examples/05_test_extensibility_engine.cpp \
    src/sdk/NativePluginLoader.cpp \
    src/sdk/LuaHotReloadEngine.cpp \
    src/sdk/WasmSandbox.cpp \
    src/sdk/PluginSupervisor.cpp \
    -Iinclude \
    -Isrc \
    -Ithird_party/wasm3/source \
    $(pkg-config --cflags --libs luajit) \
    third_party/wasm3/build/source/libm3.a \
    -lcrypto -ldl -lpthread \
    -o test_extensibility

echo "[+] Executing Complete 3-Tier Extensibility Test..."
sudo ./test_extensibility
echo "============================================================"
echo " [SUCCESS] All 3 Tiers (Native, LuaJIT, Wasm) Operational!  "
echo "============================================================"

