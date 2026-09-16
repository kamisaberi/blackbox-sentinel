#pragma once

#include "sentinel/module_interface.hpp"
#include "syscall_evaluator.hpp"
#include "container_watcher.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::cwpp {

class CwppModule : public ISentinelModule {
public:
    CwppModule();
    ~CwppModule() override = default;

    ModuleID get_id() const override { return ModuleID::CWPP; }
    const char* get_name() const override { return "09_cwpp"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<SyscallEvaluator> evaluator_;
    std::unique_ptr<ContainerWatcher> watcher_;
};

} // namespace sentinel::modules::cwpp