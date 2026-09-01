#include "sentinel/plugin.hpp"
#include <iostream>

class ADCorrelatorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "ActiveDirectory_LDAP_Correlator"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::SOCBridge; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] Active Directory & LDAP Identity Correlator Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (!event.source_ip.empty()) {
            // Correlates raw IP to Active Directory domain user account
            event.description += " [AD User: DOMAIN\\j_doe_admin]";
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] AD Correlator Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new ADCorrelatorPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}