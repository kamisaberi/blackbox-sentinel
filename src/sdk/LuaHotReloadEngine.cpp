#include "LuaHotReloadEngine.hpp"
#include <sys/inotify.h>
#include <unistd.h>
#include <poll.h>
#include <iostream>
#include <fstream>
#include <sstream>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

namespace sentinel::sdk {

// C-FFI layout definition injected into every sandboxed Lua state
static const char* LUA_FFI_CDEF = R"lua(
local ffi = require("ffi")

ffi.cdef[[
typedef struct SentinelDissectorResult {
    int      verdict;
    uint32_t threat_score;
    uint32_t rule_id;
    uint64_t semantic_tags;
    char     threat_name[64];
} SentinelDissectorResult;

typedef struct SentinelRawPacket {
    const uint8_t* data;
    size_t         length;
    uint64_t       timestamp_ns;
    uint32_t       ingress_ifindex;
    uint16_t       network_proto;
    uint8_t        transport_proto;
    uint8_t        reserved;
} SentinelRawPacket;

void     sentinel_host_log(int level, const char* sender, const char* message);
int      sentinel_host_drop_ipv4(uint32_t ipv4, uint32_t duration_sec);
void     sentinel_host_emit_metric(const char* metric_name, uint64_t delta);
uint64_t sentinel_host_monotonic_ns(void);
]]
)lua";

LuaHotReloadEngine::LuaHotReloadEngine(SentinelHostInterface host_interface,
                                       std::filesystem::path rules_directory)
    : host_iface_(host_interface), rules_dir_(std::move(rules_directory)) {
    // Initial compile on startup
    auto initial_snap = compile_rules_from_disk();
    active_snapshot_.store(initial_snap, std::memory_order_release);
}

LuaHotReloadEngine::~LuaHotReloadEngine() {
    stop();
}

bool LuaHotReloadEngine::start() {
    if (running_.load()) return true;

    if (!std::filesystem::exists(rules_dir_)) {
        std::filesystem::create_directories(rules_dir_);
    }

    inotify_fd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "LuaEngine", "Failed to initialize inotify");
        }
        return false;
    }

    watch_wd_ = inotify_add_watch(inotify_fd_, rules_dir_.c_str(),
                                  IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_TO);
    if (watch_wd_ < 0) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "LuaEngine", "Failed to add inotify watch");
        }
        close(inotify_fd_);
        inotify_fd_ = -1;
        return false;
    }

    running_.store(true);
    watcher_thread_ = std::thread(&LuaHotReloadEngine::watcher_thread_loop, this);

    if (host_iface_.log_message) {
        std::string msg = "Lua Hot-Reload Engine watching directory: " + rules_dir_.string();
        host_iface_.log_message(1, "LuaEngine", msg.c_str());
    }

    return true;
}

void LuaHotReloadEngine::stop() {
    if (!running_.load()) return;
    running_.store(false);

    if (watcher_thread_.joinable()) {
        watcher_thread_.join();
    }

    if (watch_wd_ >= 0 && inotify_fd_ >= 0) {
        inotify_rm_watch(inotify_fd_, watch_wd_);
        watch_wd_ = -1;
    }
    if (inotify_fd_ >= 0) {
        close(inotify_fd_);
        inotify_fd_ = -1;
    }

    // Cleanup active states
    auto current = active_snapshot_.exchange(nullptr);
    if (current) {
        for (auto& rule : current->rules) {
            if (rule.L) lua_close(rule.L);
        }
    }
}

void LuaHotReloadEngine::watcher_thread_loop() {
    constexpr size_t BUF_LEN = 4096;
    char buffer[BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));
    struct pollfd pfd = { inotify_fd_, POLLIN, 0 };

    while (running_.load(std::memory_order_relaxed)) {
        int poll_ret = poll(&pfd, 1, 250); // Poll every 250ms
        if (poll_ret <= 0) continue;

        ssize_t len = read(inotify_fd_, buffer, sizeof(buffer));
        if (len <= 0) continue;

        bool has_lua_event = false;
        ssize_t i = 0;
        while (i < len) {
            auto* event = reinterpret_cast<struct inotify_event*>(&buffer[i]);
            if (event->len > 0) {
                std::string fname(event->name);
                if (fname.size() > 4 && fname.substr(fname.size() - 4) == ".lua") {
                    has_lua_event = true;
                    break;
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }

        if (has_lua_event) {
            // Settle time for multi-write tools / editors
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            trigger_reload();
        }
    }
}

bool LuaHotReloadEngine::trigger_reload() {
    auto new_snapshot = compile_rules_from_disk();
    if (!new_snapshot) {
        if (host_iface_.log_message) {
            host_iface_.log_message(2, "LuaEngine", "Reload aborted: Rule compilation failed");
        }
        return false;
    }

    // RCU Pointer Swap
    auto old_snapshot = active_snapshot_.exchange(new_snapshot, std::memory_order_acq_rel);

    if (host_iface_.log_message) {
        std::string msg = "Hot-swapped to Generation " + std::to_string(new_snapshot->generation) +
                          " with " + std::to_string(new_snapshot->rules.size()) + " active rules";
        host_iface_.log_message(1, "LuaEngine", msg.c_str());
    }

    // Cleanup previous states safely
    if (old_snapshot) {
        // Sleep briefly to ensure concurrent hot-path readers finish current frame
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        for (auto& r : old_snapshot->rules) {
            if (r.L) lua_close(r.L);
        }
    }

    return true;
}

lua_State* LuaHotReloadEngine::init_sandboxed_lua_state() {
    lua_State* L = luaL_newstate();
    if (!L) return nullptr;

    // Load safe standard libraries
    luaopen_base(L);
    luaopen_string(L);
    luaopen_table(L);
    luaopen_math(L);
    luaopen_bit(L);
    luaopen_ffi(L);

    // Sandbox: Strip dangerous execution primitives
    lua_pushnil(L); lua_setglobal(L, "dofile");
    lua_pushnil(L); lua_setglobal(L, "loadfile");
    lua_pushnil(L); lua_setglobal(L, "load");
    lua_pushnil(L); lua_setglobal(L, "loadstring");

    // Execute FFI declarations
    if (luaL_dostring(L, LUA_FFI_CDEF) != 0) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "LuaEngine", lua_tostring(L, -1));
        }
        lua_close(L);
        return nullptr;
    }

    return L;
}

bool LuaHotReloadEngine::load_rule_script(lua_State* L,
                                          const std::filesystem::path& file_path,
                                          LuaRuleInstance& out_rule) {
    if (luaL_dofile(L, file_path.c_str()) != 0) {
        const char* err = lua_tostring(L, -1);
        if (host_iface_.log_message) {
            std::string msg = "Syntax error in [" + file_path.filename().string() + "]: " + (err ? err : "");
            host_iface_.log_message(3, "LuaEngine", msg.c_str());
        }
        return false;
    }

    // Verify mandatory interface: global rule table must exist
    lua_getglobal(L, "Rule");
    if (!lua_istable(L, -1)) {
        if (host_iface_.log_message) {
            std::string msg = "Missing 'Rule' table in [" + file_path.filename().string() + "]";
            host_iface_.log_message(3, "LuaEngine", msg.c_str());
        }
        return false;
    }

    // Extract Metadata
    lua_getfield(L, -1, "id");
    out_rule.rule_id = lua_isnumber(L, -1) ? static_cast<uint32_t>(lua_tonumber(L, -1)) : 9999;
    lua_pop(L, 1);

    lua_getfield(L, -1, "name");
    out_rule.rule_name = lua_isstring(L, -1) ? lua_tostring(L, -1) : file_path.stem().string();
    lua_pop(L, 1);

    lua_getfield(L, -1, "port");
    out_rule.target_port = lua_isnumber(L, -1) ? static_cast<uint64_t>(lua_tonumber(L, -1)) : 0;
    lua_pop(L, 1);

    // Verify inspect() function exists
    lua_getfield(L, -1, "inspect");
    if (!lua_isfunction(L, -1)) {
        if (host_iface_.log_message) {
            std::string msg = "Missing 'Rule.inspect(pkt, res)' function in [" + file_path.filename().string() + "]";
            host_iface_.log_message(3, "LuaEngine", msg.c_str());
        }
        return false;
    }
    lua_pop(L, 2); // pop inspect function and Rule table

    out_rule.rule_file = file_path.string();
    out_rule.L = L;
    return true;
}

std::shared_ptr<LuaRuleSnapshot> LuaHotReloadEngine::compile_rules_from_disk() {
    auto snapshot = std::make_shared<LuaRuleSnapshot>();
    snapshot->generation = ++generation_counter_;

    if (!std::filesystem::exists(rules_dir_)) {
        return snapshot;
    }

    for (const auto& entry : std::filesystem::directory_iterator(rules_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".lua") {
            lua_State* L = init_sandboxed_lua_state();
            if (!L) continue;

            LuaRuleInstance rule;
            if (load_rule_script(L, entry.path(), rule)) {
                snapshot->rules.push_back(rule);
            } else {
                lua_close(L);
            }
        }
    }

    return snapshot;
}

SentinelDissectorResult LuaHotReloadEngine::inspect_packet(const SentinelRawPacket& packet) {
    // Acquire active snapshot with zero locks
    auto snapshot = active_snapshot_.load(std::memory_order_acquire);
    if (!snapshot || snapshot->rules.empty()) {
        SentinelDissectorResult pass_res{};
        pass_res.verdict = SENTINEL_VERDICT_PASS;
        return pass_res;
    }

    SentinelDissectorResult final_verdict{};
    final_verdict.verdict = SENTINEL_VERDICT_PASS;

    for (const auto& rule : snapshot->rules) {
        lua_State* L = rule.L;
        if (!L) continue;

        // Retrieve Rule.inspect
        lua_getglobal(L, "Rule");
        lua_getfield(L, -1, "inspect");

        // Pass raw packet pointer via C-FFI
        lua_getglobal(L, "require");
        lua_pushstring(L, "ffi");
        lua_call(L, 1, 1);
        lua_getfield(L, -1, "cast");
        lua_pushstring(L, "const SentinelRawPacket*");
        lua_pushlightuserdata(L, const_cast<SentinelRawPacket*>(&packet));
        lua_call(L, 2, 1); // ffi.cast pointer

        // Call Rule.inspect(pkt_ptr) -> returns integer verdict
        // Stack: [Rule, inspect_fn, ffi_table, pkt_cdata]
        lua_remove(L, -2); // remove ffi_table
        lua_remove(L, -3); // remove Rule table

        // Now calling inspect(cdata)
        if (lua_pcall(L, 1, 1, 0) == 0) {
            if (lua_isnumber(L, -1)) {
                int action = static_cast<int>(lua_tointeger(L, -1));
                if (action == SENTINEL_VERDICT_KERNEL_DROP) {
                    final_verdict.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                    final_verdict.rule_id = rule.rule_id;
                    final_verdict.threat_score = 1000;
                    size_t copy_len = std::min(rule.rule_name.size(), sizeof(final_verdict.threat_name) - 1);
                    std::memcpy(final_verdict.threat_name, rule.rule_name.data(), copy_len);
                    final_verdict.threat_name[copy_len] = '\0';
                    lua_pop(L, 1);
                    return final_verdict; // Immediate short circuit
                } else if (action == SENTINEL_VERDICT_ALERT) {
                    final_verdict.verdict = SENTINEL_VERDICT_ALERT;
                    final_verdict.rule_id = rule.rule_id;
                    final_verdict.threat_score = 800;
                }
            }
            lua_pop(L, 1);
        } else {
            // Protected call trapped a script failure; log without crashing
            const char* err = lua_tostring(L, -1);
            if (host_iface_.log_message) {
                std::string msg = "Runtime exception in [" + rule.rule_name + "]: " + (err ? err : "");
                host_iface_.log_message(2, "LuaEngine", msg.c_str());
            }
            lua_pop(L, 1);
        }
    }

    return final_verdict;
}

size_t LuaHotReloadEngine::active_rule_count() const {
    auto snapshot = active_snapshot_.load(std::memory_order_acquire);
    return snapshot ? snapshot->rules.size() : 0;
}

uint64_t LuaHotReloadEngine::current_generation() const {
    auto snapshot = active_snapshot_.load(std::memory_order_acquire);
    return snapshot ? snapshot->generation : 0;
}

} // namespace sentinel::sdk