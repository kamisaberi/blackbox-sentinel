#include "sentinel/plugin.hpp"
#include <iostream>

class UEBAAnalyticsPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "UEBA_User_Behavior_Analytics"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] User & Entity Behavior Analytics (UEBA) Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.anomaly_score > 0.60f) {
            std::cout << "[UEBA Analytics] Flagged off-hours user behavioral anomaly." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] UEBA Analytics Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new UEBAAnalyticsPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}