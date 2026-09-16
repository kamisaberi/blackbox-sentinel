#pragma once

#include "sentinel/module_interface.hpp"
#include "device_fingerprinter.hpp"
#include "vlan_isolator.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::nac {

class NacModule : public ISentinelModule {
public:
    NacModule();
    ~NacModule() override = default;

    ModuleID get_id() const override { return ModuleID::NAC; }
    const char* get_name() const override { return "08_nac"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<DeviceFingerprinter> fingerprinter_;
    std::unique_ptr<VLANIsolator> isolator_;
};

} // namespace sentinel::modules::nac