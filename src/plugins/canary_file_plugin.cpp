#include "sentinel/plugin.hpp"
#include <iostream>

class CanaryFilePlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Canary_File_HoneyToken_Monitor"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::DeceptionTrap; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] Canary File & HoneyToken Monitor Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.description.find("canary_token") != std::string::npos) {
            std::cout << "[Canary Alert] HoneyToken accessed! Triggering immediate process isolation." << std::endl;
            event.anomaly_score = 0.99f;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] Canary File Monitor Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new CanaryFilePlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}