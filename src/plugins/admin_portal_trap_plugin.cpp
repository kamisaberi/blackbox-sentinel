#include "sentinel/plugin.hpp"
#include <iostream>

class AdminPortalTrapPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Decoy_Admin_Portal_Trap"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::DeceptionTrap; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] Decoy Admin Web Portal Trap Active (Port 8080)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 8080) {
            std::cout << "[Portal Trap] Attacker attempted login on Decoy Admin Portal! Triggering eBPF drop." << std::endl;
            event.anomaly_score = 1.00f; // Instant drop
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] Admin Portal Trap Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new AdminPortalTrapPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}