#pragma once

#include "sentinel/sdk/abi.hpp"
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <mutex>

// Forward declarations for Wasm3 opaque handles
struct M3Environment;
struct M3Runtime;
struct M3Module;
struct M3Function;

namespace sentinel::sdk {

struct LoadedWasmModule {
    std::string module_name;
    std::string file_path;
    uint32_t    rule_id{0};
    uint64_t    target_port{0};

    // Wasm3 engine handles
    M3Environment* env{nullptr};
    M3Runtime*     runtime{nullptr};
    M3Module*      module{nullptr};
    M3Function*    dissect_fn{nullptr};

    // Memory buffer cache
    uint8_t*       wasm_memory_base{nullptr};
    uint32_t       wasm_memory_size{0};
};

class WasmSandbox {
public:
    explicit WasmSandbox(SentinelHostInterface host_interface,
                         std::filesystem::path wasm_directory,
                         uint32_t stack_size_bytes = 64 * 1024);
    ~WasmSandbox();

    WasmSandbox(const WasmSandbox&) = delete;
    WasmSandbox& operator=(const WasmSandbox&) = delete;

    [[nodiscard]] bool start();
    void stop();

    /// Dispatch frame into all active Wasm sandboxes
    [[nodiscard]] SentinelDissectorResult inspect_packet(const SentinelRawPacket& packet);

    /// Load a compiled .wasm module from disk
    bool load_module(const std::filesystem::path& wasm_path);
    void unload_all();

    [[nodiscard]] size_t active_module_count() const;

private:
    static const void* host_log_bridge(M3Runtime* runtime, uint32_t level, uint32_t msg_ptr);
    static const void* host_drop_ipv4_bridge(M3Runtime* runtime, uint32_t ipv4, uint32_t duration_sec);
    static const void* host_metric_bridge(M3Runtime* runtime, uint32_t metric_ptr, uint64_t delta);
    static const void* host_monotonic_ns_bridge(M3Runtime* runtime, uint64_t* out_time_ns);

    bool link_host_functions(M3Module* module);

    SentinelHostInterface host_iface_;
    std::filesystem::path wasm_dir_;
    uint32_t stack_size_;

    std::vector<LoadedWasmModule> modules_;
    mutable std::mutex sandbox_mutex_;
};

} // namespace sentinel::sdk