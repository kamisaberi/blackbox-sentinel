#include "sentinel/ai/ThreatCorrelator.hpp"
#include <sstream>
#include <iomanip>
#include <cmath>

namespace sentinel::ai {

ThreatCorrelator::ThreatCorrelator() 
    : active_config_(std::make_shared<const InternalConfigSnapshot>()) {}

bool ThreatCorrelator::register_sensor(const SensorDefinition& def) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>(*active_config_);
    next_snapshot->sensors[def.sensor_id] = def;
    
    // Atomic pointer swap to publish new configuration
    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));
    return true;
}

bool ThreatCorrelator::unregister_sensor(uint32_t sensor_id) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>(*active_config_);
    if (next_snapshot->sensors.erase(sensor_id) == 0) {
        return false;
    }
    
    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));
    
    // Also clean up latest reading for this sensor
    std::unique_lock<std::shared_mutex> tel_lock(telemetry_mutex_);
    latest_readings_.erase(sensor_id);
    return true;
}

bool ThreatCorrelator::add_rule(const CorrelationRule& rule) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>(*active_config_);
    
    // Validate referenced sensors exist in configuration
    if (!next_snapshot->sensors.contains(rule.cyber_sensor_id) || 
        !next_snapshot->sensors.contains(rule.physical_sensor_id)) {
        return false;
    }

    // Replace if rule_id exists, otherwise append
    bool updated = false;
    for (auto& r : next_snapshot->rules) {
        if (r.rule_id == rule.rule_id) {
            r = rule;
            updated = true;
            break;
        }
    }
    if (!updated) {
        next_snapshot->rules.push_back(rule);
    }

    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));
    return true;
}

bool ThreatCorrelator::remove_rule(uint32_t rule_id) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>(*active_config_);
    auto it = std::remove_if(next_snapshot->rules.begin(), next_snapshot->rules.end(),
                             [rule_id](const CorrelationRule& r) { return r.rule_id == rule_id; });
    
    if (it == next_snapshot->rules.end()) {
        return false;
    }

    next_snapshot->rules.erase(it, next_snapshot->rules.end());
    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));
    return true;
}

void ThreatCorrelator::clear_all_rules() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>(*active_config_);
    next_snapshot->rules.clear();
    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));
}

void ThreatCorrelator::clear_all_sensors() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    auto next_snapshot = std::make_shared<InternalConfigSnapshot>();
    std::atomic_store(&active_config_, std::shared_ptr<const InternalConfigSnapshot>(next_snapshot));

    std::unique_lock<std::shared_mutex> tel_lock(telemetry_mutex_);
    latest_readings_.clear();
}

void ThreatCorrelator::update_sensor_reading(const SensorReading& reading) {
    std::unique_lock<std::shared_mutex> lock(telemetry_mutex_);
    latest_readings_[reading.sensor_id] = reading;
}

bool ThreatCorrelator::check_condition(double reading_val, RuleConditionOp op, double target_val,
                                       double min_bound, double max_bound) const noexcept {
    switch (op) {
        case RuleConditionOp::GREATER_THAN:
            return reading_val > target_val;
        case RuleConditionOp::LESS_THAN:
            return reading_val < target_val;
        case RuleConditionOp::OUT_OF_BOUNDS:
            return (reading_val < min_bound) || (reading_val > max_bound);
        case RuleConditionOp::EQUALS:
            return std::abs(reading_val - target_val) < 1e-6;
        case RuleConditionOp::RATE_OF_CHANGE_EXCEEDED:
            return std::abs(reading_val) > target_val;
        default:
            return false;
    }
}

CorrelationVerdict ThreatCorrelator::evaluate(uint32_t triggering_sensor_id) const {
    auto config = std::atomic_load(&active_config_);
    if (!config || config->rules.empty()) {
        return CorrelationVerdict{};
    }

    std::shared_lock<std::shared_mutex> tel_lock(telemetry_mutex_);

    for (const auto& rule : config->rules) {
        if (rule.cyber_sensor_id != triggering_sensor_id && rule.physical_sensor_id != triggering_sensor_id) {
            continue;
        }

        auto cyber_it = latest_readings_.find(rule.cyber_sensor_id);
        auto phys_it = latest_readings_.find(rule.physical_sensor_id);

        if (cyber_it == latest_readings_.end() || phys_it == latest_readings_.end()) {
            continue;
        }

        const auto& cyber_reading = cyber_it->second;
        const auto& phys_reading = phys_it->second;

        // Verify if Cyber channel claims NORMAL while Physical violates condition
        if (cyber_reading.status_flags == rule.expected_cyber_status) {
            auto sensor_def_it = config->sensors.find(rule.physical_sensor_id);
            double min_bound = (sensor_def_it != config->sensors.end()) ? sensor_def_it->second.min_physical_bound : 0.0;
            double max_bound = (sensor_def_it != config->sensors.end()) ? sensor_def_it->second.max_physical_bound : 0.0;

            if (check_condition(phys_reading.value, rule.condition_op, rule.trigger_value, min_bound, max_bound)) {
                CorrelationVerdict verdict;
                verdict.is_threat = true;
                verdict.threat_score = rule.base_threat_score;
                verdict.triggered_rule_id = rule.rule_id;
                verdict.action = rule.action;
                verdict.threat_name = rule.attack_signature;

                std::ostringstream ss;
                ss << "Cross-Modal Anomaly [" << rule.attack_signature << "]: Cyber sensor #"
                   << rule.cyber_sensor_id << " reported status " << cyber_reading.status_flags
                   << " (NORMAL), while physical sensor #" << rule.physical_sensor_id
                   << " violated condition with value " << std::fixed << std::setprecision(2)
                   << phys_reading.value;
                if (sensor_def_it != config->sensors.end() && !sensor_def_it->second.unit.empty()) {
                    ss << " " << sensor_def_it->second.unit;
                }
                ss << " (Threshold: " << rule.trigger_value << ")";
                verdict.explanation = ss.str();

                return verdict;
            }
        }
    }

    return CorrelationVerdict{};
}

CorrelationVerdict ThreatCorrelator::evaluate_all() const {
    auto config = std::atomic_load(&active_config_);
    if (!config || config->rules.empty()) {
        return CorrelationVerdict{};
    }

    for (const auto& rule : config->rules) {
        auto verdict = evaluate(rule.physical_sensor_id);
        if (verdict.is_threat) {
            return verdict;
        }
    }
    return CorrelationVerdict{};
}

std::optional<SensorDefinition> ThreatCorrelator::get_sensor_def(uint32_t sensor_id) const {
    auto config = std::atomic_load(&active_config_);
    if (!config) return std::nullopt;
    auto it = config->sensors.find(sensor_id);
    if (it != config->sensors.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<SensorReading> ThreatCorrelator::get_latest_reading(uint32_t sensor_id) const {
    std::shared_lock<std::shared_mutex> lock(telemetry_mutex_);
    auto it = latest_readings_.find(sensor_id);
    if (it != latest_readings_.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t ThreatCorrelator::sensor_count() const noexcept {
    auto config = std::atomic_load(&active_config_);
    return config ? config->sensors.size() : 0;
}

size_t ThreatCorrelator::rule_count() const noexcept {
    auto config = std::atomic_load(&active_config_);
    return config ? config->rules.size() : 0;
}

} // namespace sentinel::ai