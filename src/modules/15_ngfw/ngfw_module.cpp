#include "ngfw_module.hpp"
#include <iostream>

namespace sentinel::modules::ngfw {

NgfwModule::NgfwModule()
    : dpi_engine_(std::make_unique<DPIEngine>()),
      conntrack_(std::make_unique<StatefulFirewall>()) {}

bool NgfwModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 15] NGFW Deep Packet Inspection Engine initialized." << std::endl;
    return true;
}

bool NgfwModule::start() {
    running_ = true;
    std::cout << "[Module 15] NGFW Deep Packet Inspection Engine started." << std::endl;
    return true;
}

void NgfwModule::stop() {
    running_ = false;
    std::cout << "[Module 15] NGFW Deep Packet Inspection Engine stopped." << std::endl;
}

void NgfwModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.type != blackbox::EventType::NetworkPacket) return;

    // Inspect TCP flag combinations and state tracking
    FlowKey key{event.source_ip, event.destination_ip, event.port, 80};
    bool is_syn = (event.description.find("SYN") != std::string::npos);
    bool is_ack = (event.description.find("ACK") != std::string::npos);
    bool is_fin = (event.description.find("FIN") != std::string::npos);
    bool is_rst = (event.description.find("RST") != std::string::npos);

    std::string state_anomaly;
    if (!conntrack_->track_packet(key, is_syn, is_ack, is_fin, is_rst, state_anomaly)) {
        event.anomaly_score = 0.95f;
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [NGFW Stateful Alert: " + state_anomaly + "]";
    }

    // Inspect Application Protocol via DPI
    if (!event.description.empty()) {
        auto proto = dpi_engine_->inspect_payload(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size(),
            event.port
        );

        if (proto == AppProtocol::BitTorrent) {
            event.anomaly_score = 0.85f;
            event.description += " [NGFW DPI Policy: BitTorrent P2P Traffic Prohibited]";
        }
    }
}

bool NgfwModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ngfw