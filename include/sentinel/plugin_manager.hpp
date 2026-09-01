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

    // Loads a commercial plugin .so file dynamically
    bool load_plugin(const std::string& plugin_so_path, const std::string& config_json = "");

    // Unloads a loaded plugin
    void unload_plugin(const std::string& plugin_name);

    // Passes security events to all active plugins
    void dispatch_event(blackbox::SecurityEvent& event);

private:
    std::unordered_map<std::string, LoadedSentinelPlugin> plugins_;
};

} // namespace sentinel::plugin