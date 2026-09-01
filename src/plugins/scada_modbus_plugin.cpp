#include "sentinel/plugin.hpp"
#include <iostream>

class SCADAModbusInspectorPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "SCADA_Modbus_TCP_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] SCADA Modbus TCP Inspector Active (Port 502)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        // Inspect network packet events on Modbus SCADA port 502
        if (event.type == blackbox::EventType::NetworkPacket && event.port == 502) {
            std::cout << "[SCADA Inspector] Intercepted Modbus TCP traffic from IP: " << event.source_ip << std::endl;
            
            // If unauthorized PLC coil write command detected, escalate anomaly score to trigger eBPF drop
            if (event.features.size() > 2 && event.features[2] > 0.80f) {
                std::cout << "[SCADA Alert] Unauthorized PLC Write Command Detected! Triggering eBPF drop." << std::endl;
                event.anomaly_score = 0.99f; // Force critical score
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] SCADA Modbus Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() {
        return new SCADAModbusInspectorPlugin();
    }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* plugin) {
        delete plugin;
    }
}