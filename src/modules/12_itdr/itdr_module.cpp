#include "itdr_module.hpp"
#include <iostream>

namespace sentinel::modules::itdr {

ItdrModule::ItdrModule()
    : kerberos_watcher_(std::make_unique<KerberosWatcher>()),
      privilege_audit_(std::make_unique<ADPrivilegeAudit>()) {}

bool ItdrModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 12] ITDR Identity Threat Detection & Response Engine initialized." << std::endl;
    return true;
}

bool ItdrModule::start() {
    running_ = true;
    std::cout << "[Module 12] ITDR Identity Threat Detection & Response Engine started." << std::endl;
    return true;
}

void ItdrModule::stop() {
    running_ = false;
    std::cout << "[Module 12] ITDR Identity Threat Detection & Response Engine stopped." << std::endl;
}

void ItdrModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Inspect Kerberos ticket requests (Port 88)
    if (event.port == 88 || event.description.find("KERBEROS") != std::string::npos) {
        std::string violation;
        if (kerberos_watcher_->detect_kerberoasting(event.source_ip, 23, 0x40800000, violation)) {
            event.anomaly_score = 0.98f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [ITDR Alert: " + violation + "]";
        }
    }

    // Inspect Active Directory security logs
    if (event.description.find("EventID: 4728") != std::string::npos || 
        event.description.find("Domain Admins") != std::string::npos) {
        std::string alert;
        if (privilege_audit_->audit_event(4728, "Domain Admins", event.source_ip, alert)) {
            event.anomaly_score = 0.95f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [ITDR Alert: " + alert + "]";
        }
    }
}

bool ItdrModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::itdr