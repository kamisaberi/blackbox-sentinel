#pragma once

#include "sentinel/module_interface.hpp"
#include "url_classifier.hpp"
#include "outbound_proxy.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::swg {

class SwgModule : public ISentinelModule {
public:
    SwgModule();
    ~SwgModule() override = default;

    ModuleID get_id() const override { return ModuleID::SWG; }
    const char* get_name() const override { return "19_swg"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<URLClassifier> url_classifier_;
    std::unique_ptr<OutboundProxy> proxy_checker_;
};

} // namespace sentinel::modules::swg