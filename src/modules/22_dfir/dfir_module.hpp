#pragma once

#include "sentinel/module_interface.hpp"
#include "pcap_ring_buffer.hpp"
#include "evidence_signer.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::dfir {

class DfirModule : public ISentinelModule {
public:
    DfirModule();
    ~DfirModule() override = default;

    ModuleID get_id() const override { return ModuleID::DFIR; }
    const char* get_name() const override { return "22_dfir"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<PCAPRingBuffer> pcap_buffer_;
    std::unique_ptr<EvidenceSigner> signer_;
};

} // namespace sentinel::modules::dfir