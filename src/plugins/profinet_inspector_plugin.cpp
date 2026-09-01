#include "sentinel/plugin.hpp"
#include <iostream>

class ProfinetInspectorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "PROFINET_EtherNetIP_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] PROFINET & EtherNet/IP Factory Inspector Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 44818 || event.port == 34964) { // EtherNet/IP / PROFINET ports
            if (event.anomaly_score > 0.80f) {
                std::cout << "[PROFINET Inspector] Factory PLC anomaly detected from IP: " << event.source_ip << std::endl;
                event.anomaly_score = 0.98f;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] PROFINET Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new ProfinetInspectorPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}