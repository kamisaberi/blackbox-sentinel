#pragma once

#include "sentinel/module_interface.hpp"
#include "uefi_image_parser.hpp"
#include "backdoor_scanner.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::fse {

class FseModule : public ISentinelModule {
public:
    FseModule();
    ~FseModule() override = default;

    ModuleID get_id() const override { return ModuleID::FSE; }
    const char* get_name() const override { return "20_fse"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<UEFIImageParser> uefi_parser_;
    std::unique_ptr<BackdoorScanner> backdoor_scanner_;
};

} // namespace sentinel::modules::fse