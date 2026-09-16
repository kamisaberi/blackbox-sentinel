#pragma once

#include "sentinel/module_interface.hpp"
#include "memory_hook_guard.hpp"
#include "sql_interceptor.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::rasp {

class RaspModule : public ISentinelModule {
public:
    RaspModule();
    ~RaspModule() override = default;

    ModuleID get_id() const override { return ModuleID::RASP; }
    const char* get_name() const override { return "11_rasp"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<MemoryHookGuard> hook_guard_;
    std::unique_ptr<SQLInterceptor> sql_interceptor_;
};

} // namespace sentinel::modules::rasp