#include "NativePluginLoader.hpp"
#include <dlfcn.h>
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <cstring>

namespace sentinel::sdk {

// Thread-local signal isolation state
thread_local sigjmp_buf t_plugin_crash_env;
thread_local bool       t_in_plugin_execution = false;
thread_local void*      t_active_plugin_handle = nullptr;

// Global host log pointer for signal handler
static const SentinelHostInterface* g_sig_host_iface = nullptr;
static struct sigaction g_old_sa_segv;
static struct sigaction g_old_sa_bus;
static struct sigaction g_old_sa_fpe;

typedef const SentinelPluginDescriptor* (*GetDescriptorFn)(void);

void NativePluginLoader::handle_crash_signal(int sig, siginfo_t* info, void* /*ucontext*/) {
    if (t_in_plugin_execution) {
        t_in_plugin_execution = false;
        if (g_sig_host_iface && g_sig_host_iface->log_message) {
            std::string sig_name = (sig == SIGSEGV) ? "SIGSEGV (Segmentation Fault)" :
                                   (sig == SIGBUS)  ? "SIGBUS (Bus Error)" : "SIGFPE (Arithmetic Error)";
            std::string err_msg = "CRASH INTERCEPTED: Plugin fault (" + sig_name +
                                  ") at fault address: " + std::to_string(reinterpret_cast<uintptr_t>(info->si_addr)) +
                                  ". Rescuing daemon & quarantining plugin.";
            g_sig_host_iface->log_message(3, "PluginSanitizer", err_msg.c_str());
        }
        // Jump back to dispatch_packet recovery point
        siglongjmp(t_plugin_crash_env, sig);
    }

    // Unrelated crash outside of plugin execution: pass through to default OS handler
    if (sig == SIGSEGV && g_old_sa_segv.sa_sigaction) g_old_sa_segv.sa_sigaction(sig, info, nullptr);
    else if (sig == SIGBUS && g_old_sa_bus.sa_sigaction) g_old_sa_bus.sa_sigaction(sig, info, nullptr);
    else std::abort();
}

void NativePluginLoader::setup_signal_handler() {
    struct sigaction sa{};
    sa.sa_sigaction = &NativePluginLoader::handle_crash_signal;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, &g_old_sa_segv);
    sigaction(SIGBUS, &sa, &g_old_sa_bus);
    sigaction(SIGFPE, &sa, &g_old_sa_fpe);
}

NativePluginLoader::NativePluginLoader(SentinelHostInterface host_interface)
    : host_iface_(host_interface) {
    g_sig_host_iface = &host_iface_;
    setup_signal_handler();
}

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

    if (!std::filesystem::exists(so_path)) return false;

    std::string sha = calculate_sha256(so_path);

    void* handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char* err = dlerror();
        if (host_iface_.log_message) {
            host_iface_.log_message(3, "PluginLoader", err ? err : "dlopen failure");
        }
        return false;
    }

    auto get_desc_fn = reinterpret_cast<GetDescriptorFn>(dlsym(handle, "sentinel_plugin_get_descriptor"));
    if (!get_desc_fn) {
        dlclose(handle);
        return false;
    }

    const SentinelPluginDescriptor* desc = get_desc_fn();
    if (!desc || desc->magic != SENTINEL_SDK_MAGIC || desc->sdk_version_major != SENTINEL_SDK_VERSION_MAJOR) {
        dlclose(handle);
        return false;
    }

    if (desc->init_fn && desc->init_fn(&host_iface_) != 0) {
        dlclose(handle);
        return false;
    }

    LoadedPlugin lp;
    lp.handle = handle;
    lp.file_path = so_path.string();
    lp.sha256_hash = sha;
    lp.descriptor = desc;
    lp.quarantined = false;
    lp.crash_count = 0;
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
        if (lp.descriptor && lp.descriptor->shutdown_fn && !lp.quarantined) {
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
    size_t count = 0;
    for (const auto& p : plugins_) {
        if (!p.quarantined) count++;
    }
    return count;
}

size_t NativePluginLoader::quarantined_plugin_count() const {
    std::lock_guard<std::mutex> lock(loader_mutex_);
    size_t count = 0;
    for (const auto& p : plugins_) {
        if (p.quarantined) count++;
    }
    return count;
}

SentinelDissectorResult NativePluginLoader::dispatch_packet(const SentinelRawPacket& packet) {
    std::lock_guard<std::mutex> lock(loader_mutex_);
    
    SentinelDissectorResult final_res{};
    final_res.verdict = SENTINEL_VERDICT_PASS;

    for (auto& lp : plugins_) {
        if (lp.quarantined || !lp.descriptor || !lp.descriptor->dissect_fn) continue;

        // Set up thread-local signal jump boundary
        t_active_plugin_handle = lp.handle;
        t_in_plugin_execution = true;

        int sig_fault = sigsetjmp(t_plugin_crash_env, 0);
        if (sig_fault != 0) {
            // Signal occurred: Plugin crashed!
            lp.crash_count++;
            lp.quarantined = true;
            t_in_plugin_execution = false;

            if (host_iface_.log_message) {
                std::string warn = "PERMANENT QUARANTINE: Native plugin [" +
                                   std::string(lp.descriptor->plugin_name) +
                                   "] crashed and has been disabled.";
                host_iface_.log_message(3, "PluginSanitizer", warn.c_str());
            }
            continue; // Continue processing other plugins
        }

        // Execute 3rd-party code inside the boundary
        SentinelDissectorResult res = lp.descriptor->dissect_fn(&packet);
        t_in_plugin_execution = false;

        if (res.verdict == SENTINEL_VERDICT_KERNEL_DROP) {
            return res;
        } else if (res.verdict == SENTINEL_VERDICT_ALERT && final_res.verdict == SENTINEL_VERDICT_PASS) {
            final_res = res;
        }
    }

    return final_res;
}

} // namespace sentinel::sdk