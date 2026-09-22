#pragma once
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <grpcpp/grpcpp.h>

#include "common.pb.h"
#include "fleet.grpc.pb.h"
#include "telemetry.grpc.pb.h"
#include "intelligence.grpc.pb.h"
#include "model_ota.grpc.pb.h"

namespace sentinel::nexus_client {

struct NexusConfig {
    bool enabled{false};
    std::string host{"127.0.0.1"};
    uint16_t port{50051};
    uint32_t heartbeat_interval_sec{5};
    std::string site_identifier{"Edge-Substation-01"};
    std::string active_model_name{"network_threat_v1.onnx"};
};

class NexusUplink {
public:
    static NexusUplink& instance() {
        static NexusUplink inst;
        return inst;
    }

    // Starts background threads: heartbeat loop, collective defense sync, OTA checks
    bool start(const NexusConfig& config);
    void stop();

    // Stream a high-uncertainty NetFlow vector or kernel drop event to Nexus for xinfer-forge
    void stream_candidate_vector(const std::vector<float>& features, 
                                float uncertainty, 
                                float recon_loss, 
                                bool triggered_kernel_drop);

    // Broadcast a locally detected zero-day threat upstream to all other appliances in the grid
    void report_local_threat(const std::string& attacker_ip, uint32_t port, uint32_t threat_type);

    bool is_connected() const { return connected_.load(); }
    std::string get_assigned_node_id() const { return assigned_node_id_; }

private:
    NexusUplink() = default;

    bool register_appliance();
    void heartbeat_worker(std::stop_token st);
    void collective_defense_worker(std::stop_token st);
    void ota_poll_worker(std::stop_token st);

    ::sentinel::nexus::HardwareIdentity probe_hardware_identity();

    NexusConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::string assigned_node_id_{""};

    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<::sentinel::nexus::FleetService::Stub> fleet_stub_;
    std::unique_ptr<::sentinel::nexus::TelemetryService::Stub> telemetry_stub_;
    std::unique_ptr<::sentinel::nexus::IntelligenceService::Stub> intelligence_stub_;
    std::unique_ptr<::sentinel::nexus::ModelOtaService::Stub> ota_stub_;

    std::jthread heartbeat_thread_;
    std::jthread defense_thread_;
    std::jthread ota_thread_;

    mutable std::mutex threat_queue_mutex_;
    std::vector<::sentinel::nexus::ThreatIndicator> pending_threats_;
};

} // namespace sentinel::nexus_client