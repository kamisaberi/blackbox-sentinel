#pragma once

#include "sentinel/module_interface.hpp"
#include "dynamic_trust_calc.hpp"
#include "microsegment_enforcer.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ztna {

class ZtnaModule : public ISentinelModule {
public:
    ZtnaModule();
    ~ZtnaModule() override = default;

    ModuleID get_id() const override { return ModuleID::ZTNA; }
    const char* get_name() const override { return "24_ztna"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<DynamicTrustCalculator> trust_calc_;
    std::unique_ptr<MicrosegmentEnforcer> enforcer_;
};

} // namespace sentinel::modules::ztna