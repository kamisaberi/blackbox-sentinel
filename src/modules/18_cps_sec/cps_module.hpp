#pragma once

#include "sentinel/module_interface.hpp"
#include "modbus_parser.hpp"
#include "dnp3_parser.hpp"
#include "physics_validator.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::cps_sec {

class CpsModule : public ISentinelModule {
public:
    CpsModule();
    ~CpsModule() override = default;

    ModuleID get_id() const override { return ModuleID::CPS_SEC; }
    const char* get_name() const override { return "18_cps_sec"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<ModbusParser> modbus_parser_;
    std::unique_ptr<DNP3Parser> dnp3_parser_;
    std::unique_ptr<PhysicsValidator> physics_validator_;
};

} // namespace sentinel::modules::cps_sec