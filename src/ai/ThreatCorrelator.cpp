#include "ThreatCorrelator.hpp"
#include <sstream>
#include <iomanip>
#include <cmath>

namespace sentinel::ai
{

    bool ThreatCorrelator::register_sensor(const SensorDefinition &def)
    {
        std::unique_lock<std::shared_mutex> lock(config_mutex_);
        sensors_[def.sensor_id] = def;
        return true;
    }

    bool ThreatCorrelator::add_rule(const CorrelationRule &rule)
    {
        std::unique_lock<std::shared_mutex> lock(config_mutex_);
        rules_.push_back(rule);
        return true;
    }

    void ThreatCorrelator::update_sensor_reading(const SensorReading &reading)
    {
        std::unique_lock<std::shared_mutex> lock(telemetry_mutex_);
        latest_readings_[reading.sensor_id] = reading;
    }

    CorrelationVerdict ThreatCorrelator::evaluate(uint32_t triggering_sensor_id) const
    {
        std::shared_lock<std::shared_mutex> config_lock(config_mutex_);
        std::shared_lock<std::shared_mutex> tel_lock(telemetry_mutex_);

        for (const auto &rule : rules_)
        {
            if (rule.cyber_sensor_id != triggering_sensor_id && rule.physical_sensor_id != triggering_sensor_id)
            {
                continue;
            }

            auto cyber_it = latest_readings_.find(rule.cyber_sensor_id);
            auto phys_it = latest_readings_.find(rule.physical_sensor_id);

            if (cyber_it == latest_readings_.end() || phys_it == latest_readings_.end())
            {
                continue;
            }

            const auto &cyber_reading = cyber_it->second;
            const auto &phys_reading = phys_it->second;

            // Check for Cyber-Physical Discrepancy (e.g., Cyber claims NORMAL while Physical breaches limit)
            if (cyber_reading.status_flags == rule.expected_cyber_status)
            {
                bool condition_triggered = false;
                if (rule.condition_op == RuleConditionOp::GREATER_THAN && phys_reading.value > rule.trigger_value)
                {
                    condition_triggered = true;
                }
                else if (rule.condition_op == RuleConditionOp::LESS_THAN && phys_reading.value < rule.trigger_value)
                {
                    condition_triggered = true;
                }

                if (condition_triggered)
                {
                    CorrelationVerdict verdict;
                    verdict.is_threat = true;
                    verdict.threat_score = rule.base_threat_score;
                    verdict.triggered_rule_id = rule.rule_id;
                    verdict.action = rule.action;
                    verdict.threat_name = rule.rule_name;

                    std::ostringstream ss;
                    ss << "Cross-Modal Anomaly [" << rule.rule_name << "]: Cyber Channel #"
                       << rule.cyber_sensor_id << " reported NORMAL status, but Physical Sensor #"
                       << rule.physical_sensor_id << " breached threshold with value "
                       << std::fixed << std::setprecision(2) << phys_reading.value
                       << " (Trigger Threshold: " << rule.trigger_value << ")";
                    verdict.explanation = ss.str();

                    return verdict;
                }
            }
        }

        return CorrelationVerdict{};
    }

    size_t ThreatCorrelator::sensor_count() const noexcept
    {
        std::shared_lock<std::shared_mutex> lock(config_mutex_);
        return sensors_.size();
    }

    size_t ThreatCorrelator::rule_count() const noexcept
    {
        std::shared_lock<std::shared_mutex> lock(config_mutex_);
        return rules_.size();
    }

} // namespace sentinel::ai