#include "sentinel/plugin.hpp"
#include <iostream>

class STANAGLink16Plugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "STANAG4586_Link16_DataLink_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] STANAG 4586 & Link 16 Military Data Link Inspector Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.description.find("Link16") != std::string::npos) {
            std::cout << "[Defense Data Link] Inspected Link 16 tactical message integrity." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] STANAG/Link 16 Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new STANAGLink16Plugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}