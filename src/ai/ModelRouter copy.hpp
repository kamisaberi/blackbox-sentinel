#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <chrono>
#include "sentinel/sdk/abi.hpp"
#include "sdk/PluginSupervisor.hpp"
#include "ThreatCorrelator.hpp"

namespace sentinel::ai
{

    struct ModelStageConfig
    {
        std::string model_id;
        std::string format{"ONNX"};
        std::string precision{"FP16"};
        std::string silicon_target{"INTEL_NPU"};
        uint64_t latency_budget_ns{100000};
        float threshold_drop{0.85f};
        std::string xai_explainer{"MRD_XAI"};
    };

    struct TrafficRule
    {
        std::string transport{"tcp"};
        uint16_t port{0};
        std::vector<std::string> active_spkg_packages;
        std::string dissector_plugin;
        std::string owner_subsystem;
        std::string execution_mode{"CASCADE_SHORT_CIRCUIT"};
        std::vector<ModelStageConfig> model_stages;
    };

    struct SensorRouteConfig
    {
        std::string sensor_id;
        std::string sensor_type;
        std::string driver_mode;
        std::vector<TrafficRule> rules;
    };

    struct CrossModalRule
    {
        std::string correlation_id;
        std::string description;
        std::string cyber_sensor_id;
        float cyber_max_score{0.20f};
        std::string physical_sensor_id;
        float physical_min_temp{120.0f};
        std::string action{"EMERGENCY_PHYSICAL_ISOLATION"};
    };

    struct RouteExecutionResult
    {
        SentinelActionVerdict verdict{SENTINEL_VERDICT_PASS};
        std::string mitigated_by_stage; // "SPKG", "NEURAL_STAGE_1", "CROSS_MODAL"
        std::string rule_or_model_id;
        float anomaly_score{0.0f};
        uint64_t total_latency_ns{0};
        std::string mrd_xai_attribution; // e.g. "SCADA_Function_Code (54.2%)"
    };

    class ModelRouter
    {
    public:
        explicit ModelRouter(std::shared_ptr<ThreatCorrelator> correlator = nullptr);
        ~ModelRouter() = default;

        /// Load and parse configs/model_routes.yaml (zero external dependencies)
        bool load_routes(const std::filesystem::path &yaml_path);

        /// Attach dynamic ThreatCorrelator instance
        void set_threat_correlator(std::shared_ptr<ThreatCorrelator> correlator);

        /// Main 4-stage pipeline execution on an incoming frame (accepts optional true dynamic port)
        RouteExecutionResult dispatch_and_evaluate(
            const std::string &sensor_id,
            const SentinelRawPacket &packet,
            sentinel::sdk::PluginSupervisor &supervisor,
            uint16_t override_port = 0);

        /// Multi-Modal Fusion: cross-evaluates cyber state against physical sensor telemetry
        RouteExecutionResult evaluate_cross_modal_fusion(
            const std::string &cyber_sensor_id,
            float cyber_anomaly_score,
            const std::string &physical_sensor_id,
            float physical_temperature_celsius);

        [[nodiscard]] size_t total_routes() const { return routes_.size(); }
        [[nodiscard]] size_t total_fusion_rules() const { return fusion_rules_.size(); }

    private:
        std::unordered_map<std::string, SensorRouteConfig> routes_;
        std::vector<CrossModalRule> fusion_rules_;
        std::shared_ptr<ThreatCorrelator> correlator_;

        const TrafficRule *match_rule(const SensorRouteConfig &route, uint16_t port, const std::string &transport);
    };

} // namespace sentinel::ai