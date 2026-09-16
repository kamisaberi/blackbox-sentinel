#pragma once

#include "sentinel/module_interface.hpp"
#include "kerberos_watcher.hpp"
#include "ad_privilege_audit.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::itdr {

class ItdrModule : public ISentinelModule {
public:
    ItdrModule();
    ~ItdrModule() override = default;

    ModuleID get_id() const override { return ModuleID::ITDR; }
    const char* get_name() const override { return "12_itdr"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<KerberosWatcher> kerberos_watcher_;
    std::unique_ptr<ADPrivilegeAudit> privilege_audit_;
};

} // namespace sentinel::modules::itdr