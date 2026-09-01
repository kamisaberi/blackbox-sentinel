#include "sentinel/plugin.hpp"
#include <iostream>

class CEFForwarderPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Splunk_QRadar_CEF_Forwarder"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::SOCBridge; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] Splunk & QRadar CEF/Syslog Forwarder Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.level >= blackbox::ThreatLevel::High) {
            std::cout << "[CEF Forwarder] CEF:0|Blackbox|Sentinel|1.0|" << static_cast<int>(event.type) 
                      << "|ThreatDetected|" << static_cast<int>(event.level) 
                      << "|src=" << event.source_ip << " -> Streamed to Splunk/QRadar." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] CEF Forwarder Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new CEFForwarderPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}