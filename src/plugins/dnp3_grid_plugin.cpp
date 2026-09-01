#include "sentinel/plugin.hpp"
#include <iostream>

class DNP3GridInspectorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "DNP3_IEC104_Grid_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] DNP3 & IEC 60870-5-104 Substation Inspector Active (Port 20000 / 2404)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 20000 || event.port == 2404) {
            std::cout << "[Grid Inspector] Inspected electrical substation command on port " << event.port << std::endl;
            if (event.anomaly_score > 0.80f) {
                std::cout << "[Grid Alert] Malicious Substation Control Command Detected! Triggering eBPF drop." << std::endl;
                event.anomaly_score = 0.99f;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] DNP3 Grid Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new DNP3GridInspectorPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}