#pragma once

#include "sentinel/module_interface.hpp"
#include "log_correlator.hpp"
#include "time_series_engine.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::siem {

class SiemModule : public ISentinelModule {
public:
    SiemModule();
    ~SiemModule() override = default;

    ModuleID get_id() const override { return ModuleID::SIEM_CORE; }
    const char* get_name() const override { return "01_siem_core"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<LogCorrelator> correlator_;
    std::unique_ptr<TimeSeriesEngine> time_series_;
};

} // namespace sentinel::modules::siem