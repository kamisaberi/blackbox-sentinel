#pragma once

#include "sentinel/sdk/abi.hpp"
#include <string>
#include <memory>
#include <filesystem>
#include <mutex>
#include <vector>

namespace sentinel::sdk {

class NativePluginLoader {
public:
    explicit NativePluginLoader(SentinelHostInterface host_interface);
    ~NativePluginLoader();

    // Disable copy
    NativePluginLoader(const NativePluginLoader&) = delete;
    NativePluginLoader& operator=(const NativePluginLoader&) = delete;

    [[nodiscard]] bool load_plugin(const std::filesystem::path& so_path);
    void unload_all();

    [[nodiscard]] size_t active_plugin_count() const;
    [[nodiscard]] SentinelDissectorResult dispatch_packet(const SentinelRawPacket& packet);

private:
    struct LoadedPlugin {
        void* handle{nullptr};
        std::string file_path;
        std::string sha256_hash;
        const SentinelPluginDescriptor* descriptor{nullptr};
    };

    static std::string calculate_sha256(const std::filesystem::path& path);

    SentinelHostInterface host_iface_;
    std::vector<LoadedPlugin> plugins_;
    mutable std::mutex loader_mutex_;
};

} // namespace sentinel::sdk