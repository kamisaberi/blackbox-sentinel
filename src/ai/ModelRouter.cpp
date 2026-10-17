#include "ModelRouter.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace sentinel::ai
{

    ModelRouter::ModelRouter(std::shared_ptr<ThreatCorrelator> correlator)
        : correlator_(std::move(correlator)) {}

    void ModelRouter::set_threat_correlator(std::shared_ptr<ThreatCorrelator> correlator)
    {
        correlator_ = std::move(correlator);
    }

    static std::string trim_val(const std::string &s)
    {
        auto start = s.find_first_not_of(" \t\r\n\"-");
        if (start == std::string::npos)
            return "";
        auto end = s.find_last_not_of(" \t\r\n\"");
        return s.substr(start, end - start + 1);
    }

    static std::string trim_key(const std::string &s)
    {
        auto start = s.find_first_not_of(" \t\r\n-");
        if (start == std::string::npos)
            return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    bool ModelRouter::load_routes(const std::filesystem::path &yaml_path)
    {
        std::ifstream file(yaml_path);
        if (!file.is_open())
        {
            std::cerr << "[-] [ModelRouter] Cannot open routing spec: " << yaml_path << std::endl;
            return false;
        }

        routes_.clear();
        fusion_rules_.clear();

        std::string line;
        SensorRouteConfig current_sensor;
        TrafficRule current_rule;
        ModelStageConfig current_model;
        bool in_rule = false;
        bool in_model = false;

        while (std::getline(file, line))
        {
            // Strip inline comments
            auto comment_pos = line.find('#');
            if (comment_pos != std::string::npos)
            {
                line = line.substr(0, comment_pos);
            }

            auto colon_pos = line.find(':');
            if (colon_pos == std::string::npos)
                continue;

            std::string raw_key = line.substr(0, colon_pos);
            std::string raw_val = line.substr(colon_pos + 1);

            std::string key = trim_key(raw_key);
            std::string val = trim_val(raw_val);

            if (key.empty())
                continue;

            if (key == "sensor_id")
            {
                if (!current_sensor.sensor_id.empty())
                {
                    if (in_rule)
                    {
                        if (in_model)
                            current_rule.model_stages.push_back(current_model);
                        current_sensor.rules.push_back(current_rule);
                    }
                    routes_[current_sensor.sensor_id] = current_sensor;
                }
                current_sensor = SensorRouteConfig();
                current_rule = TrafficRule();
                current_model = ModelStageConfig();
                in_rule = false;
                in_model = false;
                current_sensor.sensor_id = val;
            }
            else if (key == "sensor_type")
            {
                current_sensor.sensor_type = val;
            }
            else if (key == "driver_mode")
            {
                current_sensor.driver_mode = val;
            }
            else if (key == "match")
            {
                if (in_rule)
                {
                    if (in_model)
                        current_rule.model_stages.push_back(current_model);
                    current_sensor.rules.push_back(current_rule);
                }
                current_rule = TrafficRule();
                current_model = ModelStageConfig();
                in_rule = true;
                in_model = false;
            }
            else if (key == "port")
            {
                if (!val.empty())
                    current_rule.port = static_cast<uint16_t>(std::stoul(val));
            }
            else if (key == "transport")
            {
                current_rule.transport = val;
            }
            else if (key == "package_id")
            {
                current_rule.active_spkg_packages.push_back(val);
            }
            else if (key == "plugin_id")
            {
                current_rule.dissector_plugin = val;
            }
            else if (key == "owner_subsystem")
            {
                current_rule.owner_subsystem = val;
            }
            else if (key == "execution_mode")
            {
                current_rule.execution_mode = val;
            }
            else if (key == "model_id")
            {
                if (in_model)
                {
                    current_rule.model_stages.push_back(current_model);
                }
                current_model = ModelStageConfig();
                in_model = true;
                current_model.model_id = val;
            }
            else if (key == "silicon_target")
            {
                current_model.silicon_target = val;
            }
            else if (key == "format")
            {
                current_model.format = val;
            }
            else if (key == "precision")
            {
                current_model.precision = val;
            }
            else if (key == "latency_budget_ns")
            {
                if (!val.empty())
                    current_model.latency_budget_ns = std::stoull(val);
            }
            else if (key == "threshold_drop")
            {
                if (!val.empty())
                    current_model.threshold_drop = std::stof(val);
            }
            else if (key == "xai_explainer")
            {
                current_model.xai_explainer = val;
            }
            else if (key == "correlation_id")
            {
                CrossModalRule cmr;
                cmr.correlation_id = val;
                fusion_rules_.push_back(cmr);
            }
            else if (key == "cyber_sensor_id" && !fusion_rules_.empty())
            {
                fusion_rules_.back().cyber_sensor_id = val;
            }
            else if (key == "cyber_max_score" && !fusion_rules_.empty())
            {
                if (!val.empty())
                    fusion_rules_.back().cyber_max_score = std::stof(val);
            }
            else if (key == "physical_sensor_id" && !fusion_rules_.empty())
            {
                fusion_rules_.back().physical_sensor_id = val;
            }
            else if (key == "physical_min_temp" && !fusion_rules_.empty())
            {
                if (!val.empty())
                    fusion_rules_.back().physical_min_temp = std::stof(val);
            }
            else if (key == "action" && !fusion_rules_.empty())
            {
                fusion_rules_.back().action = val;
            }
        }

        // Flush last entries
        if (in_model)
            current_rule.model_stages.push_back(current_model);
        if (in_rule)
            current_sensor.rules.push_back(current_rule);
        if (!current_sensor.sensor_id.empty())
            routes_[current_sensor.sensor_id] = current_sensor;

        std::cout << "[+] [ModelRouter] Successfully loaded routing DAG: "
                  << routes_.size() << " sensors configured | "
                  << fusion_rules_.size() << " cross-modal fusion rules active." << std::endl;

        for (const auto &f : fusion_rules_)
        {
            std::cout << "    ├── Fusion Rule: " << f.correlation_id
                      << " [Cyber: " << f.cyber_sensor_id
                      << " | Physical: " << f.physical_sensor_id << "]" << std::endl;
        }

        return true;
    }

    const TrafficRule *ModelRouter::match_rule(const SensorRouteConfig &route, uint16_t port, const std::string &transport)
    {
        for (const auto &r : route.rules)
        {
            if (r.port == port && (r.transport == transport || r.transport == "any"))
            {
                return &r;
            }
        }
        for (const auto &r : route.rules)
        {
            if (r.port == 0 || r.transport == "any")
                return &r;
        }
        return nullptr;
    }

    RouteExecutionResult ModelRouter::dispatch_and_evaluate(
        const std::string &sensor_id,
        const SentinelRawPacket &packet,
        sentinel::sdk::PluginSupervisor &supervisor,
        uint16_t override_port)
    {
        RouteExecutionResult res;
        auto t_start = std::chrono::steady_clock::now();

        auto it = routes_.find(sensor_id);
        if (it == routes_.end())
        {
            res.verdict = SENTINEL_VERDICT_PASS;
            return res;
        }

        // Dynamic Port Resolution
        uint16_t target_port = override_port;
        if (target_port == 0)
        {
            for (const auto &r : it->second.rules)
            {
                if (r.port != 0)
                {
                    target_port = r.port;
                    break;
                }
            }
        }

        const TrafficRule *rule = match_rule(it->second, target_port, "tcp");
        if (!rule)
        {
            res.verdict = SENTINEL_VERDICT_PASS;
            return res;
        }

        // -------------------------------------------------------------------------
        // STAGE 1: SPKG REFLEX GATE (< 150 ns)
        // -------------------------------------------------------------------------
        SentinelDissectorResult spkg_res = supervisor.evaluate_frame(packet);
        float score = static_cast<float>(spkg_res.threat_score) / 1000.0f; // Scaled 0-1000 to 0.0f-1.0f

        if (spkg_res.verdict == SENTINEL_VERDICT_KERNEL_DROP)
        {
            res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
            res.mitigated_by_stage = "SPKG_REFLEX_GATE";
            res.rule_or_model_id = spkg_res.threat_name;
            res.anomaly_score = score;
            res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       std::chrono::steady_clock::now() - t_start)
                                       .count();
            return res;
        }

        // -------------------------------------------------------------------------
        // STAGE 2 & 3: SUBSYSTEM & SILICON MODEL CHAIN
        // -------------------------------------------------------------------------
        for (const auto &stage : rule->model_stages)
        {
            if (score >= stage.threshold_drop)
            {
                res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                res.mitigated_by_stage = "SUBSYSTEM_" + rule->owner_subsystem;
                res.rule_or_model_id = stage.model_id + " [" + stage.silicon_target + "]";
                res.anomaly_score = score;
                res.mrd_xai_attribution = "SCADA_Function_Code Attribution | Physical_Actuator_Zone";
                res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           std::chrono::steady_clock::now() - t_start)
                                           .count();
                return res;
            }
        }

        res.verdict = SENTINEL_VERDICT_PASS;
        res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now() - t_start)
                                   .count();
        return res;
    }

    RouteExecutionResult ModelRouter::evaluate_cross_modal_fusion(
        const std::string &cyber_sensor_id,
        float cyber_anomaly_score,
        const std::string &physical_sensor_id,
        float physical_temperature_celsius)
    {
        RouteExecutionResult res;
        res.verdict = SENTINEL_VERDICT_PASS;

        // 1. Evaluate via Dynamic ThreatCorrelator engine if attached
        if (correlator_)
        {
            uint32_t cyber_id = 100;
            uint32_t phys_id = 101;
            try { cyber_id = std::stoul(cyber_sensor_id); } catch (...) {}
            try { phys_id = std::stoul(physical_sensor_id); } catch (...) {}

            SensorReading cyber_rd{cyber_id, static_cast<double>(cyber_anomaly_score), 0, 0};
            SensorReading phys_rd{phys_id, static_cast<double>(physical_temperature_celsius), 0, 0};

            correlator_->update_sensor_reading(cyber_rd);
            correlator_->update_sensor_reading(phys_rd);

            CorrelationVerdict verdict = correlator_->evaluate(cyber_id);
            if (verdict.is_threat)
            {
                res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                res.mitigated_by_stage = "DYNAMIC_CROSS_MODAL_CORRELATOR";
                res.rule_or_model_id = verdict.threat_name;
                res.anomaly_score = verdict.threat_score;
                res.mrd_xai_attribution = verdict.explanation;
                return res;
            }
        }

        // 2. Fallback to model_routes.yaml CrossModalRule list
        for (const auto &rule : fusion_rules_)
        {
            bool cyber_match = (rule.cyber_sensor_id.empty() || rule.cyber_sensor_id == cyber_sensor_id);
            bool physical_match = (rule.physical_sensor_id.empty() || rule.physical_sensor_id == physical_sensor_id);

            if (cyber_match && physical_match)
            {
                if (cyber_anomaly_score <= rule.cyber_max_score &&
                    physical_temperature_celsius >= rule.physical_min_temp)
                {
                    res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                    res.mitigated_by_stage = "CROSS_MODAL_FUSION";
                    res.rule_or_model_id = rule.correlation_id;
                    res.anomaly_score = 0.99f;
                    res.mrd_xai_attribution = "Cross-Modal Conflict: Cyber PLC reported NORMAL while Thermal Sensor measured " + std::to_string(static_cast<int>(physical_temperature_celsius)) + "°C!";
                    return res;
                }
            }
        }

        return res;
    }

} // namespace sentinel::ai