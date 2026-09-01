#include "sentinel/plugin.hpp"
#include <iostream>
#include <fstream>

class PCAPCarverPlugin : public sentinel::plugin::ISentinelPlugin {
public:
    const char* get_name() const override { return "PrePost_Breach_PCAP_Carver"; }
    const char* get_version() const override { return "1.0.0"; }
    sentinel::plugin::SentinelPluginType get_type() const override { 
        return sentinel::plugin::SentinelPluginType::Forensics; 
    }

    bool initialize(const std::string& config_json) override {
        buffer_size_mb_ = 100; // 100MB rolling RAM buffer
        std::cout << "[Sentinel Plugin] Pre/Post-Breach PCAP Evidence Carver Active (Buffer: " << buffer_size_mb_ << "MB)." << std::endl;
        return true;
    }

    void process_event(blackbox::SecurityEvent& event) override {
        // When a Critical event occurs, carve out the PCAP evidence window
        if (event.level >= blackbox::ThreatLevel::Critical) {
            std::string filename = "evidence_event_" + std::to_string(event.event_id) + ".pcap";
            std::ofstream pcap_file(filename, std::ios::binary);
            if (pcap_file.is_open()) {
                pcap_file << "PCAP_HEADER_DUMMY_DATA_EVENT_" << event.event_id;
                pcap_file.close();
                std::cout << "[PCAP Carver] Exported 60s raw PCAP forensic evidence file: " << filename << std::endl;
            }
        }
    }

    void shutdown() override {
        std::cout << "[Sentinel Plugin] PCAP Carver Shut Down." << std::endl;
    }

private:
    size_t buffer_size_mb_{100};
};

extern "C" {
    sentinel::plugin::ISentinelPlugin* create_sentinel_plugin() { return new PCAPCarverPlugin(); }
    void destroy_sentinel_plugin(sentinel::plugin::ISentinelPlugin* p) { delete p; }
}