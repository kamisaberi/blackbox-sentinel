#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <atomic>
#include <shared_mutex>
#include <optional>

namespace sentinel::ai {

enum class ModalityType : uint8_t {
    CYBER_SCADA = 0,
    THERMAL,
    VIBRATION_ACOUSTIC,
    HYDRAULIC_PRESSURE,
    CHEMICAL_PPM,
    ELECTRICAL_GRID,
    GENERIC_ACTUATOR,
    CUSTOM
};

enum class RuleConditionOp : uint8_t {
    GREATER_THAN = 0,
    LESS_THAN,
    OUT_OF_BOUNDS,
    RATE_OF_CHANGE_EXCEEDED,
    EQUALS
};

enum class CorrelationAction : uint8_t {
    PASS = 0,
    ALERT_ONLY,
    ACTUATOR_ISOLATE,
    KERNEL_DROP_AND_ISOLATE
};

struct SensorDefinition {
    uint32_t sensor_id;
    std::string name;
    ModalityType modality;
    std::string unit;
    double min_physical_bound;
    double max_physical_bound;
    double warning_threshold;
    double critical_threshold;
};

struct SensorReading {
    uint32_t sensor_id;
    double value;
    uint64_t timestamp_ns;
    uint32_t status_flags; // e.g., 0 = NORMAL, 1 = WARNING, 2 = CRITICAL
};

struct CorrelationRule {
    uint32_t rule_id;
    std::string rule_name;
    
    // Cyber reference
    uint32_t cyber_sensor_id;
    uint32_t expected_cyber_status; // e.g., 0 for NORMAL
    
    // Physical reference to correlate against
    uint32_t physical_sensor_id;
    RuleConditionOp condition_op;
    double trigger_value;
    
    CorrelationAction action;
    float base_threat_score; // 0.0f to 1.0f
    std::string attack_signature; // e.g., "STUXNET_HMI_BLINDING", "TRITON_SAFETY_OVERRIDE"
};

struct CorrelationVerdict {
    bool is_threat{false};
    float threat_score{0.0f};
    uint32_t triggered_rule_id{0};
    CorrelationAction action{CorrelationAction::PASS};
    std::string threat_name;
    std::string explanation; // XAI attribution explanation
};

class ThreatCorrelator {
public:
    ThreatCorrelator();
    ~ThreatCorrelator() = default;

    // Disallow copy, allow move
    ThreatCorrelator(const ThreatCorrelator&) = delete;
    ThreatCorrelator& operator=(const ThreatCorrelator&) = delete;
    ThreatCorrelator(ThreatCorrelator&&) noexcept = default;
    ThreatCorrelator& operator=(ThreatCorrelator&&) noexcept = default;

    // Configuration Management (Cold Path - Thread Safe)
    bool register_sensor(const SensorDefinition& def);
    bool unregister_sensor(uint32_t sensor_id);
    bool add_rule(const CorrelationRule& rule);
    bool remove_rule(uint32_t rule_id);
    void clear_all_rules();
    void clear_all_sensors();

    // Ingestion & Telemetry (Hot Path - Lock-Free / Low-Contention)
    void update_sensor_reading(const SensorReading& reading);

    // Evaluation Engine (Ultra-low Latency Fast-Path)
    [[nodiscard]] CorrelationVerdict evaluate(uint32_t triggering_sensor_id) const;
    [[nodiscard]] CorrelationVerdict evaluate_all() const;

    // State Inspection
    [[nodiscard]] std::optional<SensorDefinition> get_sensor_def(uint32_t sensor_id) const;
    [[nodiscard]] std::optional<SensorReading> get_latest_reading(uint32_t sensor_id) const;
    [[nodiscard]] size_t sensor_count() const noexcept;
    [[nodiscard]] size_t rule_count() const noexcept;

private:
    struct InternalConfigSnapshot {
        std::unordered_map<uint32_t, SensorDefinition> sensors;
        std::vector<CorrelationRule> rules;
    };

    // Configuration snapshot managed via atomic pointer swap (RCU pattern)
    std::shared_ptr<const InternalConfigSnapshot> active_config_;
    mutable std::mutex config_mutex_;

    // Live telemetry store with reader-writer lock
    mutable std::shared_mutex telemetry_mutex_;
    std::unordered_map<uint32_t, SensorReading> latest_readings_;

    // Helper evaluation logic
    [[nodiscard]] bool check_condition(double reading_val, RuleConditionOp op, double target_val, 
                                       double min_bound, double max_bound) const noexcept;
};

} // namespace sentinel::ai