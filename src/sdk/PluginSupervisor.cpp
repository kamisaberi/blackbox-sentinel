#include "PluginSupervisor.hpp"

namespace sentinel::sdk {

PluginSupervisor::PluginSupervisor(SentinelHostInterface host_iface,
                                   std::filesystem::path native_plugins_dir,
                                   std::filesystem::path lua_rules_dir)
    : host_iface_(host_iface),
      native_dir_(std::move(native_plugins_dir)),
      lua_dir_(std::move(lua_rules_dir)),
      native_loader_(host_iface_),
      lua_engine_(host_iface_, lua_dir_) {}

bool PluginSupervisor::initialize() {
    // 1. Discover and load all .so native plugins
    if (std::filesystem::exists(native_dir_)) {
        for (const auto& entry : std::filesystem::directory_iterator(native_dir_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".so") {
                native_loader_.load_plugin(entry.path());
            }
        }
    }

    // 2. Start Lua inotify file watcher
    return lua_engine_.start();
}

void PluginSupervisor::shutdown() {
    lua_engine_.stop();
    native_loader_.unload_all();
}

SentinelDissectorResult PluginSupervisor::evaluate_frame(const SentinelRawPacket& packet) {
    // Stage 1: Native C++20 plugins (< 150 ns SLA)
    SentinelDissectorResult native_res = native_loader_.dispatch_packet(packet);
    if (native_res.verdict == SENTINEL_VERDICT_KERNEL_DROP) {
        return native_res; // Immediate short-circuit
    }

    // Stage 2: LuaJIT Dynamic Hot-Reload Rules (< 450 ns SLA)
    SentinelDissectorResult lua_res = lua_engine_.inspect_packet(packet);
    if (lua_res.verdict == SENTINEL_VERDICT_KERNEL_DROP) {
        return lua_res;
    }

    // Return highest severity result
    return (lua_res.verdict != SENTINEL_VERDICT_PASS) ? lua_res : native_res;
}

} // namespace sentinel::sdk