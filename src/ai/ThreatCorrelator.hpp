#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <mutex>
#include <optional>

namespace sentinel::ai
{

    enum class ModalityType : uint8_t
    {
        CYBER_SCADA = 0,
        THERMAL,
        VIBRATION,
        PRESSURE,
        CHEMICAL,
        ELECTRICAL,
        CUSTOM
    };

    enum class RuleConditionOp : uint8_t
    {
        GREATER_THAN = 0,
        LESS_THAN,
        OUT_OF_BOUNDS
    };

    enum class CorrelationAction : uint8_t
    {
        PASS = 0,
        ALERT_ONLY,
        KERNEL_DROP_AND_ISOLATE
    };

    struct SensorDefinition
    {
        uint32_t sensor_id;
        std::string name;
        ModalityType modality;
        std::string unit;
        double min_physical_bound;
        double max_physical_bound;
        double warning_threshold;
        double critical_threshold;
    };

    struct SensorReading
    {
        uint32_t sensor_id;
        double value;
        uint64_t timestamp_ns;
        uint32_t status_flags; // 0 = NORMAL
    };

    struct CorrelationRule
    {
        uint32_t rule_id;
        std::string rule_name;
        uint32_t cyber_sensor_id;
        uint32_t expected_cyber_status;
        uint32_t physical_sensor_id;
        RuleConditionOp condition_op;
        double trigger_value;
        CorrelationAction action;
        float base_threat_score;
    };

    struct CorrelationVerdict
    {
        bool is_threat{false};
        float threat_score{0.0f};
        uint32_t triggered_rule_id{0};
        CorrelationAction action{CorrelationAction::PASS};
        std::string threat_name;
        std::string explanation;
    };

    class ThreatCorrelator
    {
    public:
        ThreatCorrelator() = default;
        ~ThreatCorrelator() = default;

        // Load configuration from YAML file path
        bool load_config_yaml(const std::string &yaml_path);

        // Register dynamic sensors and rules
        bool register_sensor(const SensorDefinition &def);
        bool add_rule(const CorrelationRule &rule);

        // Live Telemetry Ingestion (Fast-path)
        void update_sensor_reading(const SensorReading &reading);

        // Evaluation Engine
        [[nodiscard]] CorrelationVerdict evaluate(uint32_t triggering_sensor_id) const;

        [[nodiscard]] size_t sensor_count() const noexcept;
        [[nodiscard]] size_t rule_count() const noexcept;

    private:
        mutable std::shared_mutex config_mutex_;
        std::unordered_map<uint32_t, SensorDefinition> sensors_;
        std::vector<CorrelationRule> rules_;

        mutable std::shared_mutex telemetry_mutex_;
        std::unordered_map<uint32_t, SensorReading> latest_readings_;
    };

} // namespace sentinel::ai