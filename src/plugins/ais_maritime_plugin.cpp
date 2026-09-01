#include "sentinel/plugin.hpp"
#include <iostream>

class AISMaritimePlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "AIS_Maritime_Telemetry_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] AIS Maritime Vessel Telemetry Inspector Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.description.find("AIS") != std::string::npos || event.port == 10110) {
            if (event.anomaly_score > 0.80f) {
                std::cout << "[AIS Maritime Alert] Vessel Telemetry Spoofing / Dark Fleet Activity Detected!" << std::endl;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] AIS Maritime Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new AISMaritimePlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}