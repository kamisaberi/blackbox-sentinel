#include "WasmSandbox.hpp"
#include <wasm3.h>
#include <m3_env.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace sentinel::sdk {

static thread_local const SentinelHostInterface* g_active_host_iface = nullptr;

WasmSandbox::WasmSandbox(SentinelHostInterface host_interface,
                         std::filesystem::path wasm_directory,
                         uint32_t stack_size_bytes)
    : host_iface_(host_interface),
      wasm_dir_(std::move(wasm_directory)),
      stack_size_(stack_size_bytes) {}

WasmSandbox::~WasmSandbox() {
    stop();
}

bool WasmSandbox::start() {
    std::lock_guard<std::mutex> lock(sandbox_mutex_);

    if (!std::filesystem::exists(wasm_dir_)) {
        std::filesystem::create_directories(wasm_dir_);
    }

    for (const auto& entry : std::filesystem::directory_iterator(wasm_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".wasm") {
            load_module(entry.path());
        }
    }

    if (host_iface_.log_message) {
        std::string msg = "Wasm Micro-Sandbox initialized with " +
                          std::to_string(modules_.size()) + " active sandboxed modules";
        host_iface_.log_message(1, "WasmSandbox", msg.c_str());
    }

    return true;
}

void WasmSandbox::stop() {
    unload_all();
}

void WasmSandbox::unload_all() {
    std::lock_guard<std::mutex> lock(sandbox_mutex_);
    for (auto& mod : modules_) {
        if (mod.runtime) {
            m3_FreeRuntime(mod.runtime);
        }
        if (mod.env) {
            m3_FreeEnvironment(mod.env);
        }
    }
    modules_.clear();
}

// -----------------------------------------------------------------------------
// Host Callback Bridges (Wasm3 C-API)
// -----------------------------------------------------------------------------

m3ApiRawFunction(m3_bridge_log) {
    m3ApiGetArg(uint32_t, level);
    m3ApiGetArgMem(const char*, msg);

    if (g_active_host_iface && g_active_host_iface->log_message) {
        g_active_host_iface->log_message(static_cast<int>(level), "WasmModule", msg ? msg : "");
    }
    m3ApiSuccess();
}

m3ApiRawFunction(m3_bridge_drop_ipv4) {
    m3ApiReturnType(int32_t); // <--- Required to declare raw_return
    m3ApiGetArg(uint32_t, ipv4);
    m3ApiGetArg(uint32_t, duration_sec);

    int ret = 0;
    if (g_active_host_iface && g_active_host_iface->request_ebpf_drop_ip) {
        ret = g_active_host_iface->request_ebpf_drop_ip(ipv4, duration_sec);
    }
    m3ApiReturn(ret);
}

m3ApiRawFunction(m3_bridge_metric) {
    m3ApiGetArgMem(const char*, metric_name);
    m3ApiGetArg(uint64_t, delta);

    if (g_active_host_iface && g_active_host_iface->emit_metric_counter) {
        g_active_host_iface->emit_metric_counter(metric_name ? metric_name : "", delta);
    }
    m3ApiSuccess();
}

m3ApiRawFunction(m3_bridge_time_ns) {
    m3ApiReturnType(uint64_t); // <--- Required to declare raw_return

    uint64_t t = 0;
    if (g_active_host_iface && g_active_host_iface->get_monotonic_time_ns) {
        t = g_active_host_iface->get_monotonic_time_ns();
    }
    m3ApiReturn(t);
}

bool WasmSandbox::link_host_functions(M3Module* module) {
    M3Result res = m3Err_none;

    res = m3_LinkRawFunction(module, "env", "sentinel_host_log", "v(ii)", m3_bridge_log);
    if (res && res != m3Err_functionLookupFailed) return false;

    res = m3_LinkRawFunction(module, "env", "sentinel_host_drop_ipv4", "i(ii)", m3_bridge_drop_ipv4);
    if (res && res != m3Err_functionLookupFailed) return false;

    res = m3_LinkRawFunction(module, "env", "sentinel_host_emit_metric", "v(iI)", m3_bridge_metric);
    if (res && res != m3Err_functionLookupFailed) return false;

    res = m3_LinkRawFunction(module, "env", "sentinel_host_monotonic_ns", "I()", m3_bridge_time_ns);
    if (res && res != m3Err_functionLookupFailed) return false;

    return true;
}

bool WasmSandbox::load_module(const std::filesystem::path& wasm_path) {
    std::ifstream file(wasm_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return false;
    }

    IM3Environment env = m3_NewEnvironment();
    if (!env) return false;

    IM3Runtime runtime = m3_NewRuntime(env, stack_size_, nullptr);
    if (!runtime) {
        m3_FreeEnvironment(env);
        return false;
    }

    IM3Module module = nullptr;
    M3Result res = m3_ParseModule(env, &module, buffer.data(), buffer.size());
    if (res) {
        if (host_iface_.log_message) {
            std::string err = "Wasm ParseModule failed: " + std::string(res);
            host_iface_.log_message(3, "WasmSandbox", err.c_str());
        }
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    res = m3_LoadModule(runtime, module);
    if (res) {
        if (host_iface_.log_message) {
            std::string err = "Wasm LoadModule failed: " + std::string(res);
            host_iface_.log_message(3, "WasmSandbox", err.c_str());
        }
        m3_FreeModule(module);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    link_host_functions(module);

    IM3Function dissect_fn = nullptr;
    res = m3_FindFunction(&dissect_fn, runtime, "sentinel_dissect");
    if (res || !dissect_fn) {
        if (host_iface_.log_message) {
            std::string err = "Wasm export 'sentinel_dissect' missing in: " + wasm_path.filename().string();
            host_iface_.log_message(3, "WasmSandbox", err.c_str());
        }
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    LoadedWasmModule mod;
    mod.module_name = wasm_path.stem().string();
    mod.file_path = wasm_path.string();
    mod.env = env;
    mod.runtime = runtime;
    mod.module = module;
    mod.dissect_fn = dissect_fn;
    mod.rule_id = 7001;

    modules_.push_back(mod);
    return true;
}

SentinelDissectorResult WasmSandbox::inspect_packet(const SentinelRawPacket& packet) {
    std::lock_guard<std::mutex> lock(sandbox_mutex_);

    SentinelDissectorResult final_res{};
    final_res.verdict = SENTINEL_VERDICT_PASS;

    if (modules_.empty() || !packet.data || packet.length == 0) {
        return final_res;
    }

    g_active_host_iface = &host_iface_;

    for (auto& mod : modules_) {
        // Query module's linear memory using mod.module and size_t
        size_t mem_size = 0;
        uint8_t* mem_base = m3_GetMemory(mod.module, &mem_size, 0);

        if (!mem_base || mem_size < 4096 + packet.length) {
            continue;
        }

        // Copy raw frame into linear memory scratch buffer (offset 0x1000)
        constexpr uint32_t PKT_OFFSET = 0x1000;
        size_t copy_bytes = std::min(packet.length, mem_size - PKT_OFFSET);
        std::memcpy(mem_base + PKT_OFFSET, packet.data, copy_bytes);

        // Execute sandboxed dissector: sentinel_dissect(PKT_OFFSET, copy_bytes)
        M3Result res = m3_CallV(mod.dissect_fn, PKT_OFFSET, static_cast<uint32_t>(copy_bytes));
        if (res) {
            if (host_iface_.log_message) {
                std::string err = "Wasm execution trap in [" + mod.module_name + "]: " + std::string(res);
                host_iface_.log_message(2, "WasmSandbox", err.c_str());
            }
            continue;
        }

        int32_t verdict_val = 0;
        m3_GetResultsV(mod.dissect_fn, &verdict_val);

        if (verdict_val == SENTINEL_VERDICT_KERNEL_DROP) {
            final_res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
            final_res.rule_id = mod.rule_id;
            final_res.threat_score = 1000;
            size_t name_len = std::min(mod.module_name.size(), sizeof(final_res.threat_name) - 1);
            std::memcpy(final_res.threat_name, mod.module_name.data(), name_len);
            final_res.threat_name[name_len] = '\0';
            g_active_host_iface = nullptr;
            return final_res;
        } else if (verdict_val == SENTINEL_VERDICT_ALERT && final_res.verdict == SENTINEL_VERDICT_PASS) {
            final_res.verdict = SENTINEL_VERDICT_ALERT;
            final_res.rule_id = mod.rule_id;
            final_res.threat_score = 800;
        }
    }

    g_active_host_iface = nullptr;
    return final_res;
}

size_t WasmSandbox::active_module_count() const {
    std::lock_guard<std::mutex> lock(sandbox_mutex_);
    return modules_.size();
}

} // namespace sentinel::sdk