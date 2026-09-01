#include "sentinel/plugin.hpp"
#include <iostream>

class MAVLinkInspectorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "MAVLink_Drone_Telemetry_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] MAVLink Drone Telemetry Inspector Active (UAV Defense)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.description.find("MAVLink") != std::string::npos || event.port == 14550) {
            if (event.anomaly_score > 0.75f) {
                std::cout << "[MAVLink Defense] Drone Telemetry Spoofing / Control Hijack Detected! IP: " 
                          << event.source_ip << std::endl;
                event.anomaly_score = 0.99f;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] MAVLink Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new MAVLinkInspectorPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}