#!/usr/bin/env bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo "    BLACKBOX-SENTINEL: MASTER ECOSYSTEM COMPILATION         "
echo "============================================================"

# 1. Build Wasm3 static library if needed
if [ ! -f "third_party/wasm3/build/source/libm3.a" ]; then
    echo "[+] Building third_party/wasm3 runtime..."
    if [ ! -d "third_party/wasm3" ]; then
        mkdir -p third_party
        git clone --depth 1 https://github.com/wasm3/wasm3.git third_party/wasm3
    fi
    cd third_party/wasm3
    mkdir -p build && cd build
    cmake .. -DBUILD_WASI=none -DCMAKE_BUILD_TYPE=Release
    make -j"$(nproc)" m3
    cd "$PROJECT_ROOT"
fi

# 2. Build CMake targets (sentinel, tools, test suites)
echo "[+] Building CMake targets (sentinel, tools, tests)..."
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)" sentinel test_extensibility sentinel_plugin_pack nexus_rule_broadcaster
cd "$PROJECT_ROOT"

# 3. Build Reference Plugins
echo "[+] Building Native C++ Modbus Plugin..."
(
    cd plugins/native/modbus_guard
    mkdir -p build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j"$(nproc)"
)

if command -v clang &> /dev/null && [ -f "plugins/wasm/dicom_phi_guard/dicom_phi_guard.c" ]; then
    echo "[+] Compiling C WebAssembly DICOM Plugin..."
    clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export=sentinel_dissect \
        -o plugins/wasm/dicom_phi_guard/dicom_phi_guard.wasm \
        plugins/wasm/dicom_phi_guard/dicom_phi_guard.c
fi

if command -v cargo &> /dev/null && [ -d "plugins/wasm/s7comm_guard" ]; then
    echo "[+] Compiling Rust WebAssembly S7Comm Plugin..."
    (
        cd plugins/wasm/s7comm_guard
        cargo build --target wasm32-unknown-unknown --release --quiet
    )
fi

# 4. Sync rules and plugins to /etc/sentinel
echo "[+] Synchronizing extensions to /etc/sentinel/..."
./tools/sync_extensions.sh

echo "============================================================"
echo " [SUCCESS] All targets, tools, and plugins built cleanly!   "
echo " Binaries located in: build/                                "
echo "   - build/sentinel                                         "
echo "   - build/test_extensibility                               "
echo "   - build/sentinel-plugin-pack                             "
echo "   - build/nexus-rule-broadcaster                           "
echo "============================================================"
