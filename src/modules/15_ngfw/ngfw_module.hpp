#pragma once

#include "sentinel/module_interface.hpp"
#include "dpi_engine.hpp"
#include "stateful_firewall.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ngfw {

class NgfwModule : public ISentinelModule {
public:
    NgfwModule();
    ~NgfwModule() override = default;

    ModuleID get_id() const override { return ModuleID::NGFW; }
    const char* get_name() const override { return "15_ngfw"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<DPIEngine> dpi_engine_;
    std::unique_ptr<StatefulFirewall> conntrack_;
};

} // namespace sentinel::modules::ngfw