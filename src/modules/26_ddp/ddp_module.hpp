#pragma once

#include "sentinel/module_interface.hpp"
#include "decoy_plc_trap.hpp"
#include "decoy_ssh_trap.hpp"
#include "honey_token_monitor.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ddp {

class DdpModule : public ISentinelModule {
public:
    DdpModule();
    ~DdpModule() override = default;

    ModuleID get_id() const override { return ModuleID::DDP; }
    const char* get_name() const override { return "26_ddp"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<DecoyPLCTrap> plc_trap_;
    std::unique_ptr<DecoySSHTrap> ssh_trap_;
    std::unique_ptr<HoneyTokenMonitor> token_monitor_;
};

} // namespace sentinel::modules::ddp