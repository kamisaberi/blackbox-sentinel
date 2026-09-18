#include "dfir_module.hpp"
#include <iostream>

namespace sentinel::modules::dfir {

DfirModule::DfirModule()
    : pcap_buffer_(std::make_unique<PCAPRingBuffer>(50000)),
      signer_(std::make_unique<EvidenceSigner>()) {}

bool DfirModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 22] DFIR Forensics & Evidence Carver initialized." << std::endl;
    return true;
}

bool DfirModule::start() {
    running_ = true;
    std::cout << "[Module 22] DFIR Forensics & Evidence Carver started." << std::endl;
    return true;
}

void DfirModule::stop() {
    running_ = false;
    std::cout << "[Module 22] DFIR Forensics & Evidence Carver stopped." << std::endl;
}

void DfirModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Buffer network packet
    if (event.type == blackbox::EventType::NetworkPacket && !event.description.empty()) {
        pcap_buffer_->push_packet(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size()
        );
    }

    // On Critical threat alerts, carve out a forensic PCAP window and seal evidence
    if (event.level == blackbox::ThreatLevel::Critical) {
        std::string pcap_file = "evidence_incident_" + std::to_string(event.event_id) + ".pcap";
        if (pcap_buffer_->dump_to_pcap(pcap_file, std::chrono::seconds(60))) {
            std::string receipt;
            signer_->seal_evidence(pcap_file, "INC-" + std::to_string(event.event_id), receipt);
            event.description += " [DFIR Preserved: " + receipt + "]";
        }
    }
}

bool DfirModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::dfir