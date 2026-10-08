#pragma once

#include "sentinel/sdk/abi.hpp"
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <mutex>
#include <csetjmp>
#include <csignal>

namespace sentinel::sdk {

class NativePluginLoader {
public:
    explicit NativePluginLoader(SentinelHostInterface host_interface);
    ~NativePluginLoader();

    NativePluginLoader(const NativePluginLoader&) = delete;
    NativePluginLoader& operator=(const NativePluginLoader&) = delete;

    [[nodiscard]] bool load_plugin(const std::filesystem::path& so_path);
    void unload_all();

    [[nodiscard]] size_t active_plugin_count() const;
    [[nodiscard]] size_t quarantined_plugin_count() const;
    [[nodiscard]] SentinelDissectorResult dispatch_packet(const SentinelRawPacket& packet);

    // Internal signal recovery callback
    static void handle_crash_signal(int sig, siginfo_t* info, void* ucontext);

private:
    struct LoadedPlugin {
        void* handle{nullptr};
        std::string file_path;
        std::string sha256_hash;
        const SentinelPluginDescriptor* descriptor{nullptr};
        bool quarantined{false};
        uint32_t crash_count{0};
    };

    static std::string calculate_sha256(const std::filesystem::path& path);
    void setup_signal_handler();

    SentinelHostInterface host_iface_;
    std::vector<LoadedPlugin> plugins_;
    mutable std::mutex loader_mutex_;
};

} // namespace sentinel::sdk