#pragma once

#include "sentinel/module_interface.hpp"
#include "dicom_pacs_guard.hpp"
#include "hl7_telemetry_audit.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::iot_sec {

class IotModule : public ISentinelModule {
public:
    IotModule();
    ~IotModule() override = default;

    ModuleID get_id() const override { return ModuleID::IOT_SEC; }
    const char* get_name() const override { return "17_iot_sec"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<DICOMPACSGuard> dicom_guard_;
    std::unique_ptr<HL7TelemetryAudit> hl7_audit_;
};

} // namespace sentinel::modules::iot_sec