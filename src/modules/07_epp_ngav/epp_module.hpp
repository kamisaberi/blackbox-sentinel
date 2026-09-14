#pragma once

#include "sentinel/module_interface.hpp"
#include "file_entropy_calc.hpp"
#include "binary_pe_parser.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::epp_ngav {

class EppModule : public ISentinelModule {
public:
    EppModule();
    ~EppModule() override = default;

    ModuleID get_id() const override { return ModuleID::EPP_NGAV; }
    const char* get_name() const override { return "07_epp_ngav"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<FileEntropyCalculator> entropy_calc_;
    std::unique_ptr<BinaryPEParser> binary_parser_;
};

} // namespace sentinel::modules::epp_ngav