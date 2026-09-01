#include "sentinel/plugin_manager.hpp"
#include <dlfcn.h>
#include <iostream>

namespace sentinel::plugin {

SentinelPluginManager::~SentinelPluginManager() {
    for (auto& [name, loaded] : plugins_) {
        if (loaded.instance) {
            loaded.instance->shutdown();
            if (loaded.destroy_func) {
                loaded.destroy_func(loaded.instance.release());
            }
        }
        if (loaded.handle_ptr) {
            dlclose(loaded.handle_ptr);
        }
    }
    plugins_.clear();
}

bool SentinelPluginManager::load_plugin(const std::string& plugin_so_path, const std::string& config_json) {
    void* handle = dlopen(plugin_so_path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        std::cerr << "[Sentinel Plugin Error] dlopen failed for " << plugin_so_path << ": " << dlerror() << std::endl;
        return false;
    }

    auto create_func = reinterpret_cast<CreateSentinelPluginFunc>(dlsym(handle, "create_sentinel_plugin"));
    auto destroy_func = reinterpret_cast<DestroySentinelPluginFunc>(dlsym(handle, "destroy_sentinel_plugin"));

    if (!create_func || !destroy_func) {
        std::cerr << "[Sentinel Plugin Error] Failed to resolve plugin symbols in " << plugin_so_path << std::endl;
        dlclose(handle);
        return false;
    }

    ISentinelPlugin* raw_instance = create_func();
    if (!raw_instance) {
        dlclose(handle);
        return false;
    }

    std::string name = raw_instance->get_name();
    if (!raw_instance->initialize(config_json)) {
        destroy_func(raw_instance);
        dlclose(handle);
        return false;
    }

    LoadedSentinelPlugin loaded;
    loaded.handle_ptr = handle;
    loaded.instance = std::unique_ptr<ISentinelPlugin>(raw_instance);
    loaded.destroy_func = destroy_func;

    std::cout << "[Sentinel Commercial Add-On] Loaded Plugin: " << name 
              << " (v" << raw_instance->get_version() << ") from " << plugin_so_path << std::endl;

    plugins_[name] = std::move(loaded);
    return true;
}

void SentinelPluginManager::unload_plugin(const std::string& plugin_name) {
    auto it = plugins_.find(plugin_name);
    if (it != plugins_.end()) {
        if (it->second.instance) {
            it->second.instance->shutdown();
            if (it->second.destroy_func) {
                it->second.destroy_func(it->second.instance.release());
            }
        }
        if (it->second.handle_ptr) {
            dlclose(it->second.handle_ptr);
        }
        plugins_.erase(it);
        std::cout << "[Sentinel Plugin] Unloaded: " << plugin_name << std::endl;
    }
}

void SentinelPluginManager::dispatch_event(blackbox::SecurityEvent& event) {
    for (auto& [name, loaded] : plugins_) {
        if (loaded.instance) {
            loaded.instance->process_event(event);
        }
    }
}

} // namespace sentinel::plugin