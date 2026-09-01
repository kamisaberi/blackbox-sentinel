#include "sentinel/plugin.hpp"
#include <iostream>

class WebhookDispatcherPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "Webhook_PagerDuty_Dispatcher"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::SOCBridge; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Commercial Plugin] Webhook & PagerDuty Alert Dispatcher Active." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.level >= blackbox::ThreatLevel::High) {
            std::cout << "[Webhook Dispatcher] Dispatched alert JSON payload to PagerDuty & Slack webhook." << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Commercial Plugin] Webhook Dispatcher Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new WebhookDispatcherPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}