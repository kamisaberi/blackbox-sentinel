#include "sentinel/plugin.hpp"
#include <iostream>

class ActiveDeceptionTrapPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Active_Deception_Honeypot_Trap"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::DeceptionTrap; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] Active Deception Honeypot Trap Active (Decoy Ports: 2222, 23, 8080)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        // If attacker connects to a decoy honeypot port (e.g., 2222 or 23 Telnet)
        if (event.port == 2222 || event.port == 23) {
            std::cout << "[Deception Alert] Attacker probed Decoy Trap Port (" << event.port 
                      << ") from IP: " << event.source_ip << "! Executing immediate eBPF drop." << std::endl;
            event.anomaly_score = 1.00f; // Force instant eBPF drop
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] Active Deception Trap Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() {
        return new ActiveDeceptionTrapPlugin();
    }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* plugin) {
        delete plugin;
    }
}