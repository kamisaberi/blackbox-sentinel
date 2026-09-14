#pragma once

#include "sentinel/module_interface.hpp"
#include "signature_matcher.hpp"
#include "xdp_packet_dropper.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ids_ips {

class IdsIpsModule : public ISentinelModule {
public:
    IdsIpsModule();
    ~IdsIpsModule() override = default;

    ModuleID get_id() const override { return ModuleID::IDS_IPS; }
    const char* get_name() const override { return "04_ids_ips"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<SignatureMatcher> matcher_;
    std::unique_ptr<XDPPacketDropper> dropper_;
};

} // namespace sentinel::modules::ids_ips