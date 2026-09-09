#pragma once

#include "sentinel/module_interface.hpp"
#include "syn_flood_guard.hpp"
#include "udp_rate_limiter.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ddos {

class DdosModule : public ISentinelModule {
public:
    DdosModule();
    ~DdosModule() override = default;

    ModuleID get_id() const override { return ModuleID::DDOS; }
    const char* get_name() const override { return "13_ddos"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<SYNFloodGuard> syn_guard_;
    std::unique_ptr<UDPRateLimiter> udp_limiter_;
};

} // namespace sentinel::modules::ddos