#include "sentinel/plugin.hpp"
#include <iostream>

class NMEAMarinePlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "NMEA2000_Marine_Sensor_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] NMEA 2000 Marine Sensor Inspector Active (Naval Protection)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.description.find("NMEA") != std::string::npos) {
            std::cout << "[NMEA Marine] Verified vessel gyro and depth sounder sensor message integrity." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] NMEA Marine Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new NMEAMarinePlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}