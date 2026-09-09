#pragma once

#include "sentinel/module_interface.hpp"
#include "login_velocity.hpp"
#include "geo_velocity_check.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ato {

class AtoModule : public ISentinelModule {
public:
    AtoModule();
    ~AtoModule() override = default;

    ModuleID get_id() const override { return ModuleID::ATO; }
    const char* get_name() const override { return "14_ato"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<LoginVelocityTracker> velocity_tracker_;
    std::unique_ptr<GeoVelocityCheck> geo_check_;
};

} // namespace sentinel::modules::ato