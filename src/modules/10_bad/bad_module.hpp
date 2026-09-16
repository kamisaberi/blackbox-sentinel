#pragma once

#include "sentinel/module_interface.hpp"
#include "mouse_keystroke_nn.hpp"
#include "tcp_fingerprinter.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::bad {

class BadModule : public ISentinelModule {
public:
    BadModule();
    ~BadModule() override = default;

    ModuleID get_id() const override { return ModuleID::BAD; }
    const char* get_name() const override { return "10_bad"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<MouseKeystrokeNN> kinematics_evaluator_;
    std::unique_ptr<TCPFingerprinter> tcp_fingerprinter_;
};

} // namespace sentinel::modules::bad