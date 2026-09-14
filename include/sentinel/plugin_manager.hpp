#pragma once

#include "plugin.hpp"
#include <string>
#include <unordered_map>
#include <memory>
#include <vector>

namespace sentinel::plugin {

struct LoadedSentinelPlugin {
    void* handle_ptr{nullptr};
    std::unique_ptr<ISentinelPlugin> instance;
    DestroySentinelPluginFunc destroy_func{nullptr};
};

class SentinelPluginManager {
public:
    SentinelPluginManager() = default;
    ~SentinelPluginManager();

    // Dynamically loads a .so plugin
    bool load_plugin(const std::string& plugin_so_path, const std::string& config_json = "");

    // Unloads a specific plugin by name
    void unload_plugin(const std::string& plugin_name);

    // Dispatches events across all active loaded plugins
    void dispatch_event(blackbox::SecurityEvent& event);

    // Checks if a plugin is loaded
    bool is_loaded(const std::string& plugin_name);

    // Returns count of active plugins
    size_t loaded_count();

private:
    std::unordered_map<std::string, LoadedSentinelPlugin> plugins_;
};

} // namespace sentinel::plugin