#pragma once

#include "sentinel/module_interface.hpp"
#include "sentinel/event_bus.hpp"
#include "sentinel/config_manager.hpp"
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

namespace sentinel::core {

class Orchestrator {
public:
    Orchestrator();
    ~Orchestrator();

    bool bootstrap_all_modules(const std::string& config_dir = "configs/modules");
    void shutdown_all_modules();
    
    size_t active_module_count() const;

private:
    std::vector<std::shared_ptr<ISentinelModule>> modules_;
    std::atomic<bool> is_running_{false};
    mutable std::mutex orchestrator_mutex_;
};

} // namespace sentinel::core