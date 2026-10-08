// In PluginSupervisor.cpp:
#include "PluginSupervisor.hpp"

namespace sentinel::sdk {

PluginSupervisor::PluginSupervisor(SentinelHostInterface host_iface,
                                   std::filesystem::path native_plugins_dir,
                                   std::filesystem::path lua_rules_dir,
                                   std::filesystem::path wasm_modules_dir)
    : host_iface_(host_iface),
      native_dir_(std::move(native_plugins_dir)),
      lua_dir_(std::move(lua_rules_dir)),
      wasm_dir_(std::move(wasm_modules_dir)),
      native_loader_(host_iface_),
      lua_engine_(host_iface_, lua_dir_),
      wasm_sandbox_(host_iface_, wasm_dir_) {}

bool PluginSupervisor::initialize() {
    // 1. Tier A: Native C++20 Plugins
    if (std::filesystem::exists(native_dir_)) {
        for (const auto& entry : std::filesystem::directory_iterator(native_dir_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".so") {
                native_loader_.load_plugin(entry.path());
            }
        }
    }

    // 2. Tier C: LuaJIT Dynamic Rules
    lua_engine_.start();

    // 3. Tier B: Wasm Micro-Sandbox Modules
    wasm_sandbox_.start();

    return true;
}

void PluginSupervisor::shutdown() {
    wasm_sandbox_.stop();
    lua_engine_.stop();
    native_loader_.unload_all();
}

SentinelDissectorResult PluginSupervisor::evaluate_frame(const SentinelRawPacket& packet) {
    // Tier A: Native C++20 Line-Rate Dissectors (< 150 ns SLA)
    SentinelDissectorResult res = native_loader_.dispatch_packet(packet);
    if (res.verdict == SENTINEL_VERDICT_KERNEL_DROP) return res;

    // Tier C: LuaJIT Dynamic Hot-Reload Rules (< 450 ns SLA)
    SentinelDissectorResult lua_res = lua_engine_.inspect_packet(packet);
    if (lua_res.verdict == SENTINEL_VERDICT_KERNEL_DROP) return lua_res;
    if (lua_res.verdict != SENTINEL_VERDICT_PASS) res = lua_res;

    // Tier B: Wasm Micro-Sandbox Plugins (< 2.5 µs SLA)
    SentinelDissectorResult wasm_res = wasm_sandbox_.inspect_packet(packet);
    if (wasm_res.verdict == SENTINEL_VERDICT_KERNEL_DROP) return wasm_res;
    if (wasm_res.verdict != SENTINEL_VERDICT_PASS) res = wasm_res;

    return res;
}

} // namespace sentinel::sdk