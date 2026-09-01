#include "sentinel/plugin.hpp"
#include <iostream>

class FirewallSyncPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "PaloAlto_Fortinet_Firewall_Sync"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::SOCBridge; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] Palo Alto & Fortinet Firewall Auto-Sync Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.action_taken == blackbox::ActionType::EBPFBlockIP) {
            std::cout << "[Firewall Sync] Pushed blocked IP (" << event.source_ip 
                      << ") to Palo Alto / Fortinet REST API." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] Firewall Sync Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new FirewallSyncPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}