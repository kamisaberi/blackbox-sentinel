#pragma once

#include "sentinel/module_interface.hpp"
#include "http_payload_eval.hpp"
#include "api_logic_inspector.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::waf {

class WafModule : public ISentinelModule {
public:
    WafModule();
    ~WafModule() override = default;

    ModuleID get_id() const override { return ModuleID::WAF; }
    const char* get_name() const override { return "05_waf"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<HTTPPayloadEvaluator> payload_evaluator_;
    std::unique_ptr<APILogicInspector> logic_inspector_;
};

} // namespace sentinel::modules::waf