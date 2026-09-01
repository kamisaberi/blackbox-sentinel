#include "sentinel/plugin.hpp"
#include <iostream>

class S7CommOPCUAPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Siemens_S7Comm_OPCUA_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] Siemens S7Comm & OPC UA Inspector Active (Port 102 / 4840)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 102 || event.port == 4840) {
            std::cout << "[S7Comm/OPCUA] Intercepted Siemens S7 / OPC UA PLC command from " << event.source_ip << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] S7Comm Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new S7CommOPCUAPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}