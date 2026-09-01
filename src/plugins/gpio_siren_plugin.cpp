#include "sentinel/plugin.hpp"
#include <iostream>

class GPIOSirenPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "GPIO_Hardware_Siren_Relay"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::PhysicalSecurity; 
    }

    bool initialize(const std::string& config_json) override {
        gpio_pin_ = 18;
        std::cout << "[Sentinel Plugin] GPIO Hardware Siren Relay Active (Pin " << gpio_pin_ << ")." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.level == blackbox::ThreatLevel::Critical) {
            std::cout << "[GPIO Hardware] Triggering physical alarm siren on GPIO Pin " << gpio_pin_ << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] GPIO Siren Relay Shut Down." << std::endl;
    }

private:
    int gpio_pin_{18};
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new GPIOSirenPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}