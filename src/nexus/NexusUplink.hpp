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
    uint16_t nexus_http_port{9443};
    uint16_t sentinel_local_api_port{8443};
    uint32_t heartbeat_interval_sec{5};
    std::string site_identifier{"Edge-Substation-01"};
    std::string active_model_name{"network_threat_v1.onnx"};
    std::string local_models_dir{"models"};
};

class NexusUplink {
public:
    static NexusUplink& instance() {
        static NexusUplink inst;
        return inst;
    }

    bool start(const NexusConfig& config);
    void stop();

    void stream_candidate_vector(const std::vector<float>& features, 
                                float uncertainty, 
                                float recon_loss, 
                                bool triggered_kernel_drop);

    void report_local_threat(const std::string& attacker_ip, uint32_t port, uint32_t threat_type);

    bool is_connected() const { return connected_.load(); }
    std::string get_assigned_node_id() const { return assigned_node_id_; }

private:
    NexusUplink() = default;

    bool register_appliance();
    void send_graceful_disconnect(const std::string& reason);
    void heartbeat_worker(std::stop_token st);
    void collective_defense_worker(std::stop_token st);
    void ota_poll_worker(std::stop_token st);

    // OTA Auto-Download and Hot-Reload
    bool handle_model_update(const ::sentinel::nexus::ModelPollResponse& ota_resp);
    bool download_model_http(const std::string& download_path, const std::string& dest_file);
    bool verify_file_sha256(const std::string& file_path, const std::string& expected_sha256);
    bool trigger_local_sentinel_reload(const std::string& model_filename);

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