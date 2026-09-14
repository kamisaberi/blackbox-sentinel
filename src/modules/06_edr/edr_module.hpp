#pragma once

#include "sentinel/module_interface.hpp"
#include "process_tracker.hpp"
#include "memory_scanner.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::edr {

class EdrModule : public ISentinelModule {
public:
    EdrModule();
    ~EdrModule() override = default;

    ModuleID get_id() const override { return ModuleID::EDR; }
    const char* get_name() const override { return "06_edr"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<ProcessTracker> process_tracker_;
    std::unique_ptr<MemoryScanner> memory_scanner_;
};

} // namespace sentinel::modules::edr