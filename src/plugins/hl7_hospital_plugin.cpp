#include "sentinel/plugin.hpp"
#include <iostream>

class HL7HospitalPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "HL7_FHIR_Hospital_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] HL7 / FHIR Hospital Telemetry Inspector Active (Port 2575)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 2575) {
            std::cout << "[HL7 Hospital] Inspected patient health record stream from IP: " << event.source_ip << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] HL7 Hospital Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new HL7HospitalPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}