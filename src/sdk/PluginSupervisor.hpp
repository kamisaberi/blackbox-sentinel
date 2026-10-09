// In PluginSupervisor.hpp:
#pragma once

#include "NativePluginLoader.hpp"
#include "LuaHotReloadEngine.hpp"
#include "WasmSandbox.hpp"

namespace sentinel::sdk
{

    struct ExtensionStats
    {
        std::string id;
        std::string name;
        uint32_t tier; // 0=Native, 1=Wasm, 2=Lua
        uint64_t frames_evaluated{0};
        uint64_t kernel_drops{0};
        uint64_t alerts{0};
        uint64_t avg_latency_ns{0};
        uint64_t max_latency_ns{0};
        bool quarantined{false};
    };

    class PluginSupervisor
    {
    public:
        PluginSupervisor(SentinelHostInterface host_iface,
                         std::filesystem::path native_plugins_dir,
                         std::filesystem::path lua_rules_dir,
                         std::filesystem::path wasm_modules_dir);

        bool initialize();
        void shutdown();

        [[nodiscard]] SentinelDissectorResult evaluate_frame(const SentinelRawPacket &packet);

        NativePluginLoader &native_loader() { return native_loader_; }
        LuaHotReloadEngine &lua_engine() { return lua_engine_; }
        WasmSandbox &wasm_sandbox() { return wasm_sandbox_; }

    private:
        SentinelHostInterface host_iface_;
        std::filesystem::path native_dir_;
        std::filesystem::path lua_dir_;
        std::filesystem::path wasm_dir_;

        NativePluginLoader native_loader_;
        LuaHotReloadEngine lua_engine_;
        WasmSandbox wasm_sandbox_;
    };

} // namespace sentinel::sdk