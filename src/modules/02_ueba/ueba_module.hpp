#pragma once

#include "sentinel/module_interface.hpp"
#include "behavior_matrix.hpp"
#include "baseline_scorer.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ueba {

class UebaModule : public ISentinelModule {
public:
    UebaModule();
    ~UebaModule() override = default;

    ModuleID get_id() const override { return ModuleID::UEBA; }
    const char* get_name() const override { return "02_ueba"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<BehaviorMatrix> matrix_;
    std::unique_ptr<BaselineScorer> scorer_;
};

} // namespace sentinel::modules::ueba