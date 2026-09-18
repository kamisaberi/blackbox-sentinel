#include "sentinel/config_manager.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

namespace sentinel {

std::string ConfigManager::read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool ConfigManager::load_global_config(const std::string& config_file_path) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    global_config_json_ = read_file(config_file_path);
    if (global_config_json_.empty()) {
        std::cerr << "[ConfigManager Warning] Could not open global config: " << config_file_path << std::endl;
        return false;
    }
    return true;
}

bool ConfigManager::load_module_config(ModuleID id, const std::string& modules_dir) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    std::string mod_name = module_id_to_string(id);
    
    // Strip numeric prefix if present (e.g., "01_siem_core" -> "siem_core.json")
    size_t underscore_pos = mod_name.find('_');
    std::string filename = (underscore_pos != std::string::npos) ? mod_name.substr(underscore_pos + 1) : mod_name;
    std::string full_path = modules_dir + "/" + filename + ".json";

    std::string content = read_file(full_path);
    if (content.empty()) {
        // Fallback: search relative to parent
        full_path = "../" + full_path;
        content = read_file(full_path);
    }

    if (!content.empty()) {
        module_configs_[id] = content;
        return true;
    }

    // Assign minimal default JSON if file is not on disk
    module_configs_[id] = "{\"enabled\": true}";
    return true;
}

std::string ConfigManager::get_module_config(ModuleID id) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    auto it = module_configs_.find(id);
    if (it != module_configs_.end()) {
        return it->second;
    }
    return "{\"enabled\": true}";
}

std::string ConfigManager::get_global_config() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return global_config_json_;
}

bool ConfigManager::has_module_config(ModuleID id) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return module_configs_.find(id) != module_configs_.end();
}

} // namespace sentinel