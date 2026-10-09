To eliminate one-off manual `g++` and `clang` commands, we will integrate all tools, test suites, and reference plugins directly into the official **CMake build trees** and provide automated **master build scripts** for both `blackbox-sentinel` and `blackbox-essential`.

---

# Part 1: `blackbox-sentinel` Integration

We will add the following first-class build targets to `blackbox-sentinel`:
1. **`test_extensibility`** (`examples/05_test_extensibility_engine.cpp`)
2. **`sentinel-plugin-pack`** (`tools/sdk/sentinel_plugin_pack.cpp`)
3. **`nexus-rule-broadcaster`** (`tools/nexus_rule_broadcaster.cpp`)

---

### Step 1.1: Update `blackbox-sentinel/CMakeLists.txt`

Open `/home/kami/blackbox-sentinel/CMakeLists.txt`. Without removing any existing lines, add these targets right below the existing module test executables section at the bottom of the file:

```cmake
# -------------------------------------------------------------------
# EXTENSIBILITY SUBSYSTEM TOOLS & TEST TARGETS
# -------------------------------------------------------------------

# 1. End-to-End Extensibility Test Suite (Native + LuaJIT + Wasm3)
add_executable(test_extensibility
    examples/05_test_extensibility_engine.cpp
    src/sdk/NativePluginLoader.cpp
    src/sdk/LuaHotReloadEngine.cpp
    src/sdk/WasmSandbox.cpp
    src/sdk/PluginSupervisor.cpp
    src/nexus/KernelDropInjector.cpp
)
target_link_libraries(test_extensibility PRIVATE
    ${LUAJIT_LIBRARIES}
    ${BPF_LIB}
    ${ELF_LIB}
    OpenSSL::Crypto
    Threads::Threads
    ${CMAKE_DL_LIBS}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wasm3/build/source/libm3.a
)

# 2. Cryptographic Packaging & Signing CLI (sentinel-plugin-pack)
add_executable(sentinel_plugin_pack
    tools/sdk/sentinel_plugin_pack.cpp
)
target_link_libraries(sentinel_plugin_pack PRIVATE
    OpenSSL::Crypto
)
set_target_properties(sentinel_plugin_pack PROPERTIES
    OUTPUT_NAME "sentinel-plugin-pack"
)

# 3. Nexus Dynamic Rule Broadcaster CLI (nexus-rule-broadcaster)
add_executable(nexus_rule_broadcaster
    tools/nexus_rule_broadcaster.cpp
    src/nexus/DynamicRuleReceiver.cpp
)
target_link_libraries(nexus_rule_broadcaster PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)
set_target_properties(nexus_rule_broadcaster PROPERTIES
    OUTPUT_NAME "nexus-rule-broadcaster"
)

# Optional: Install CLI tools into /usr/local/bin
install(TARGETS 
    sentinel_plugin_pack 
    nexus_rule_broadcaster
    DESTINATION /usr/local/bin
)
```

---

### Step 1.2: Create Master Build & Test Script for `blackbox-sentinel`

Create a single script, `/home/kami/blackbox-sentinel/build_all.sh`, that builds Wasm3, the main appliance daemon, all tools, tests, plugins (Rust Wasm, C Wasm, Native C++), and syncs rules to `/etc/sentinel/`:

```bash
cat << 'EOF' > /home/kami/blackbox-sentinel/build_all.sh
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
EOF

chmod +x /home/kami/blackbox-sentinel/build_all.sh
```

---

# Part 2: `blackbox-essential` Integration

We will add the **`test_af_xdp`** and **`test_af_xdp_live`** executables directly as CMake targets in `blackbox-essential`.

---

### Step 2.1: Update `blackbox-essential/CMakeLists.txt`

Open `/home/kami/blackbox-essential/CMakeLists.txt` and append the test executable targets at the bottom of the file right before `install()`:

```cmake
# -------------------------------------------------------------------
# AF_XDP EXAMPLES & BENCHMARKS
# -------------------------------------------------------------------
add_executable(test_af_xdp examples/test_af_xdp.cpp)
target_link_libraries(test_af_xdp PRIVATE
    blackbox::blackbox
    ${XDP_LIB}
    bpf
    Threads::Threads
)

add_executable(test_af_xdp_live examples/test_af_xdp_live.cpp)
target_link_libraries(test_af_xdp_live PRIVATE
    blackbox::blackbox
    ${XDP_LIB}
    bpf
    Threads::Threads
)
```

---

### Step 2.2: Create Master Build & Test Script for `blackbox-essential`

Create `/home/kami/blackbox-essential/scripts/build_all.sh` to compile eBPF CO-RE bytecode, `libblackbox.so`, and all AF_XDP binaries in one step:

```bash
cat << 'EOF' > /home/kami/blackbox-essential/scripts/build_all.sh
#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo "    BLACKBOX-ESSENTIAL: MASTER CORE COMPILATION             "
echo "============================================================"

# 1. Compile eBPF CO-RE Kernel Bytecode (xdp_drop.o)
echo "[+] Compiling eBPF CO-RE Kernel bytecode..."
./scripts/build_ebpf.sh

# 2. Build CMake Shared Library (libblackbox.so) and Executables
echo "[+] Compiling libblackbox.so, daemon, and AF_XDP targets..."
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)" blackbox blackbox_daemon test_af_xdp test_af_xdp_live

# 3. Install to system library path
echo "[+] Installing libblackbox.so to /usr/local/lib..."
sudo make install
sudo ldconfig
cd "$PROJECT_ROOT"

echo "============================================================"
echo " [SUCCESS] Core engine & AF_XDP binaries built cleanly!     "
echo " Output binaries:                                           "
echo "   - build/libblackbox.so (installed to /usr/local/lib)     "
echo "   - build/blackbox_daemon                                  "
echo "   - build/test_af_xdp                                      "
echo "   - build/test_af_xdp_live                                 "
echo "============================================================"
EOF

chmod +x /home/kami/blackbox-essential/scripts/build_all.sh
```

---

# Part 3: Verification Step by Step

### Test Build 1: `blackbox-essential`
Run the new master script:

```bash
cd /home/kami/blackbox-essential
./scripts/build_all.sh
```

Now run the live wire test directly from CMake's output folder without manual compilation commands:
```bash
sudo ./build/test_af_xdp_live
```

---

### Test Build 2: `blackbox-sentinel`
Run the new master script:

```bash
cd /home/kami/blackbox-sentinel
./build_all.sh
```

Now run all tools directly from CMake's `build/` directory:

```bash
# 1. Run the Extensibility Test Suite
sudo ./build/test_extensibility

# 2. Inspect active plugin telemetry via the main binary
sudo ./build/sentinel --plugins-status

# 3. Test the signing CLI
./build/sentinel-plugin-pack
```

All one-off `g++` and `clang` commands are replaced by standard CMake targets and automated shell scripts.