#include "sentinel/plugin.hpp"
#include <iostream>

class BACnetInspectorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "BACnet_SmartBuilding_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] BACnet Smart Building HVAC Inspector Active (Port 47808)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 47808) {
            std::cout << "[BACnet Inspector] Inspected Smart Building HVAC control traffic from IP: " << event.source_ip << std::endl;
            if (event.anomaly_score > 0.80f) {
                std::cout << "[BACnet Alert] Unauthorized Building Control Command Detected! Triggering eBPF drop." << std::endl;
                event.anomaly_score = 0.98f;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] BACnet Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new BACnetInspectorPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}