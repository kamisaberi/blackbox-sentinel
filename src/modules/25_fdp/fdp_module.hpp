#pragma once

#include "sentinel/module_interface.hpp"
#include "transaction_graph.hpp"
#include "synthetic_id_filter.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::fdp {

class FdpModule : public ISentinelModule {
public:
    FdpModule();
    ~FdpModule() override = default;

    ModuleID get_id() const override { return ModuleID::FDP; }
    const char* get_name() const override { return "25_fdp"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<TransactionGraph> graph_;
    std::unique_ptr<SyntheticIDFilter> id_filter_;
};

} // namespace sentinel::modules::fdp