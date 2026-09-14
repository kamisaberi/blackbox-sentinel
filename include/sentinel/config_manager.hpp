#pragma once

#include "module_interface.hpp"
#include <string>
#include <unordered_map>
#include <mutex>
#include <filesystem>

namespace sentinel {

class ConfigManager {
public:
    static ConfigManager& instance() {
        static ConfigManager manager;
        return manager;
    }

    // Load global appliance config
    bool load_global_config(const std::string& config_file_path);

    // Load module-specific config from configs/modules/<module_name>.json
    bool load_module_config(ModuleID id, const std::string& modules_dir = "configs/modules");

    // Retrieve raw JSON string for a specific module
    std::string get_module_config(ModuleID id);

    // Retrieve global JSON config
    std::string get_global_config();

    // Check if configuration exists
    bool has_module_config(ModuleID id);

private:
    ConfigManager() = default;
    ~ConfigManager() = default;

    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    std::string read_file(const std::string& path);

    std::string global_config_json_;
    std::unordered_map<ModuleID, std::string> module_configs_;
    std::mutex config_mutex_;
};

} // namespace sentinel