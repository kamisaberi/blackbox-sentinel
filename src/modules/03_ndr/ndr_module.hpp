#pragma once

#include "sentinel/module_interface.hpp"
#include "flow_analyzer.hpp"
#include "eta_fingerprinter.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ndr {

class NdrModule : public ISentinelModule {
public:
    NdrModule();
    ~NdrModule() override = default;

    ModuleID get_id() const override { return ModuleID::NDR; }
    const char* get_name() const override { return "03_ndr"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<FlowAnalyzer> flow_analyzer_;
    std::unique_ptr<ETAFingerprinter> eta_fingerprinter_;
};

} // namespace sentinel::modules::ndr