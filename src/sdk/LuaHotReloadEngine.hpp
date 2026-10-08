#pragma once

#include "sentinel/sdk/abi.hpp"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <filesystem>
#include <unordered_map>

// Forward declarations for Lua C API
struct lua_State;

namespace sentinel::sdk {

struct LuaRuleInstance {
    std::string rule_file;
    std::string rule_name;
    uint32_t    rule_id{0};
    uint64_t    target_port{0}; // 0 = all ports
    lua_State*  L{nullptr};
};

struct LuaRuleSnapshot {
    std::vector<LuaRuleInstance> rules;
    uint64_t generation{0};
};

class LuaHotReloadEngine {
public:
    LuaHotReloadEngine(SentinelHostInterface host_interface,
                       std::filesystem::path rules_directory);
    ~LuaHotReloadEngine();

    LuaHotReloadEngine(const LuaHotReloadEngine&) = delete;
    LuaHotReloadEngine& operator=(const LuaHotReloadEngine&) = delete;

    [[nodiscard]] bool start();
    void stop();

    /// Hot-path packet inspection called per frame (lock-free RCU acquire)
    [[nodiscard]] SentinelDissectorResult inspect_packet(const SentinelRawPacket& packet);

    /// Force immediate reload (can also be invoked via Sentinel Nexus gRPC signal)
    bool trigger_reload();

    [[nodiscard]] size_t active_rule_count() const;
    [[nodiscard]] uint64_t current_generation() const;

private:
    void watcher_thread_loop();
    [[nodiscard]] std::shared_ptr<LuaRuleSnapshot> compile_rules_from_disk();
    lua_State* init_sandboxed_lua_state();
    bool load_rule_script(lua_State* L, const std::filesystem::path& file_path, LuaRuleInstance& out_rule);

    SentinelHostInterface host_iface_;
    std::filesystem::path rules_dir_;

    std::atomic<bool> running_{false};
    std::thread       watcher_thread_;
    int               inotify_fd_{-1};
    int               watch_wd_{-1};

    // RCU pointer swap for zero-wait lock-free readers
    std::atomic<std::shared_ptr<LuaRuleSnapshot>> active_snapshot_{nullptr};
    std::atomic<uint64_t> generation_counter_{0};
};

} // namespace sentinel::sdk