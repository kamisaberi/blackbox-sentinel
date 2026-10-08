#include "NativePluginLoader.hpp"
#include <dlfcn.h>
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace sentinel::sdk {

typedef const SentinelPluginDescriptor* (*GetDescriptorFn)(void);

NativePluginLoader::NativePluginLoader(SentinelHostInterface host_interface)
    : host_iface_(host_interface) {}

NativePluginLoader::~NativePluginLoader() {
    unload_all();
}

std::string NativePluginLoader::calculate_sha256(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool NativePluginLoader::load_plugin(const std::filesystem::path& so_path) {
    std::lock_guard<std::mutex> lock(loader_mutex_);

    if (!std::filesystem::exists(so_path)) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", ("File not found: " + so_path.string()).c_str());
        }
        return false;
    }

    std::string sha = calculate_sha256(so_path);

    // Open library with private symbols to prevent symbol collision
    void* handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char* err = dlerror();
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", err ? err : "Unknown dlopen error");
        }
        return false;
    }

    // Resolve entry point
    auto get_desc_fn = reinterpret_cast<GetDescriptorFn>(dlsym(handle, "sentinel_plugin_get_descriptor"));
    if (!get_desc_fn) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", "Symbol 'sentinel_plugin_get_descriptor' not found");
        }
        dlclose(handle);
        return false;
    }

    const SentinelPluginDescriptor* desc = get_desc_fn();
    if (!desc) {
        dlclose(handle);
        return false;
    }

    // Verify magic bytes and major SDK version
    if (desc->magic != SENTINEL_SDK_MAGIC || desc->sdk_version_major != SENTINEL_SDK_VERSION_MAJOR) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", "Incompatible SDK Magic or Version");
        }
        dlclose(handle);
        return false;
    }

    // Initialize plugin with host interfaces
    if (desc->init_fn && desc->init_fn(&host_iface_) != 0) {
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", "Plugin init_fn returned error");
        }
        dlclose(handle);
        return false;
    }

    LoadedPlugin lp;
    lp.handle = handle;
    lp.file_path = so_path.string();
    lp.sha256_hash = sha;
    lp.descriptor = desc;
    plugins_.push_back(lp);

    if (host_iface_.log_message) {
        std::string ok_msg = "Loaded plugin: " + std::string(desc->plugin_name) +
                             " [" + desc->plugin_version + "] (SHA: " + sha.substr(0, 8) + "...)";
        host_iface_.log_message(1, "PluginLoader", ok_msg.c_str());
    }

    return true;
}

void NativePluginLoader::unload_all() {
    std::lock_guard<std::mutex> lock(loader_mutex_);
    for (auto& lp : plugins_) {
        if (lp.descriptor && lp.descriptor->shutdown_fn) {
            lp.descriptor->shutdown_fn();
        }
        if (lp.handle) {
            dlclose(lp.handle);
        }
    }
    plugins_.clear();
}

size_t NativePluginLoader::active_plugin_count() const {
    std::lock_guard<std::mutex> lock(loader_mutex_);
    return plugins_.size();
}

SentinelDissectorResult NativePluginLoader::dispatch_packet(const SentinelRawPacket& packet) {
    std::lock_guard<std::mutex> lock(loader_mutex_);
    
    SentinelDissectorResult final_res{};
    final_res.verdict = SENTINEL_VERDICT_PASS;

    for (const auto& lp : plugins_) {
        if (!lp.descriptor || !lp.descriptor->dissect_fn) continue;

        SentinelDissectorResult res = lp.descriptor->dissect_fn(&packet);
        if (res.verdict == SENTINEL_VERDICT_KERNEL_DROP) {
            // Immediate short-circuit on drop
            return res;
        } else if (res.verdict == SENTINEL_VERDICT_ALERT && final_res.verdict == SENTINEL_VERDICT_PASS) {
            final_res = res;
        }
    }

    return final_res;
}

} // namespace sentinel::sdk