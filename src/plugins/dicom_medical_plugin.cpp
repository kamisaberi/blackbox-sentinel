#include "sentinel/plugin.hpp"
#include <iostream>

class DICOMMedicalPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "DICOM_Medical_Imaging_Inspector"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::ProtocolInspector; 
    }

    bool initialize(const std::string& config_json) override {
        std::cout << "[Sentinel Plugin] DICOM Medical Imaging PACS Inspector Active (Port 104)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        if (event.port == 104) {
            std::cout << "[DICOM Medical] Inspected hospital PACS medical imaging traffic from IP: " << event.source_ip << std::endl;
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] DICOM Medical Inspector Shut Down." << std::endl;
    }
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new DICOMMedicalPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}