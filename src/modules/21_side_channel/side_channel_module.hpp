#pragma once

#include "sentinel/module_interface.hpp"
#include "power_trace_eval.hpp"
#include "em_noise_detector.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::side_channel {

class SideChannelModule : public ISentinelModule {
public:
    SideChannelModule();
    ~SideChannelModule() override = default;

    ModuleID get_id() const override { return ModuleID::SIDE_CHANNEL; }
    const char* get_name() const override { return "21_side_channel"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<PowerTraceEvaluator> power_evaluator_;
    std::unique_ptr<EMNoiseDetector> em_detector_;
};

} // namespace sentinel::modules::side_channel