#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo "    SYNCING ARYORITHM RULES & PLUGINS TO /etc/sentinel/     "
echo "============================================================"

# 1. Create target directories with correct ownership
sudo mkdir -p /etc/sentinel/rules.d
sudo mkdir -p /etc/sentinel/wasm.d
sudo mkdir -p /etc/sentinel/plugins.d
sudo chown -R "$USER:$USER" /etc/sentinel

# 2. Sync all Lua dynamic rules
echo "[+] Syncing Lua threat rules to /etc/sentinel/rules.d/..."
cp -v rules/lua/*.lua /etc/sentinel/rules.d/

# 3. Build & Sync Rust S7Comm WebAssembly plugin if cargo is available
if command -v cargo &> /dev/null && [ -d "plugins/wasm/s7comm_guard" ]; then
    echo "[+] Building Rust Wasm S7Comm plugin..."
    (
        cd plugins/wasm/s7comm_guard
        cargo build --target wasm32-unknown-unknown --release --quiet
        cp -v target/wasm32-unknown-unknown/release/wasm_s7comm_guard.wasm /etc/sentinel/wasm.d/
    )
fi

# 4. Sync DICOM Wasm plugin if compiled
if [ -f "examples/plugins/wasm_dicom_anonymity/dicom_phi_guard.c" ] && command -v clang &> /dev/null; then
    echo "[+] Compiling C DICOM Wasm plugin..."
    clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export=sentinel_dissect \
        -o /etc/sentinel/wasm.d/dicom_phi_guard.wasm \
        examples/plugins/wasm_dicom_anonymity/dicom_phi_guard.c
fi

# 5. Build & Sync Native Modbus C++ plugin
if [ -d "plugins/native/modbus_guard" ]; then
    echo "[+] Building Native C++ Modbus plugin..."
    (
        cd plugins/native/modbus_guard
        mkdir -p build && cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null
        make -j"$(nproc)" > /dev/null
        cp -v sentinel_modbus_guard.so /etc/sentinel/plugins.d/
    )
fi

echo "------------------------------------------------------------"
echo "[SUCCESS] All community rules & plugins deployed to /etc/sentinel/"
echo "Run: 'sudo ./build/sentinel --plugins-status' to verify."
echo "============================================================"

