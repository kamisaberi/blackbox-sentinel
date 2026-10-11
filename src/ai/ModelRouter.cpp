#include "ModelRouter.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace sentinel::ai
{

    static std::string trim(const std::string &s)
    {
        auto start = s.find_first_not_of(" \t\r\n\"");
        if (start == std::string::npos)
            return "";
        auto end = s.find_last_not_of(" \t\r\n\"");
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

        // Zero-dependency robust YAML section parser
        while (std::getline(file, line))
        {
            // Strip comments
            auto comment_pos = line.find('#');
            if (comment_pos != std::string::npos)
            {
                line = line.substr(0, comment_pos);
            }
            std::string trimmed = trim(line);
            if (trimmed.empty())
                continue;

            if (trimmed.rfind("- sensor_id:", 0) == 0)
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
                in_rule = false;
                in_model = false;
                current_sensor.sensor_id = trim(trimmed.substr(12));
            }
            else if (trimmed.rfind("sensor_type:", 0) == 0)
            {
                current_sensor.sensor_type = trim(trimmed.substr(12));
            }
            else if (trimmed.rfind("- match:", 0) == 0)
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
            else if (trimmed.rfind("port:", 0) == 0)
            {
                current_rule.port = static_cast<uint16_t>(std::stoul(trim(trimmed.substr(5))));
            }
            else if (trimmed.rfind("transport:", 0) == 0)
            {
                current_rule.transport = trim(trimmed.substr(10));
            }
            else if (trimmed.rfind("- package_id:", 0) == 0)
            {
                current_rule.active_spkg_packages.push_back(trim(trimmed.substr(13)));
            }
            else if (trimmed.rfind("plugin_id:", 0) == 0)
            {
                current_rule.dissector_plugin = trim(trimmed.substr(10));
            }
            else if (trimmed.rfind("owner_subsystem:", 0) == 0)
            {
                current_rule.owner_subsystem = trim(trimmed.substr(16));
            }
            else if (trimmed.rfind("- model_id:", 0) == 0)
            {
                if (in_model)
                {
                    current_rule.model_stages.push_back(current_model);
                }
                current_model = ModelStageConfig();
                in_model = true;
                current_model.model_id = trim(trimmed.substr(11));
            }
            else if (trimmed.rfind("silicon_target:", 0) == 0)
            {
                current_model.silicon_target = trim(trimmed.substr(15));
            }
            else if (trimmed.rfind("threshold_drop:", 0) == 0)
            {
                current_model.threshold_drop = std::stof(trim(trimmed.substr(15)));
            }
            else if (trimmed.rfind("xai_explainer:", 0) == 0)
            {
                current_model.xai_explainer = trim(trimmed.substr(14));
            }
            else if (trimmed.rfind("- correlation_id:", 0) == 0)
            {
                CrossModalRule cmr;
                cmr.correlation_id = trim(trimmed.substr(17));
                fusion_rules_.push_back(cmr);
            }
            else if (trimmed.rfind("cyber_sensor_id:", 0) == 0 && !fusion_rules_.empty())
            {
                fusion_rules_.back().cyber_sensor_id = trim(trimmed.substr(16));
            }
            else if (trimmed.rfind("physical_sensor_id:", 0) == 0 && !fusion_rules_.empty())
            {
                fusion_rules_.back().physical_sensor_id = trim(trimmed.substr(19));
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
        // Fallback to wildcard rule if port didn't match
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
        sentinel::sdk::PluginSupervisor &supervisor)
    {
        RouteExecutionResult res;
        auto t_start = std::chrono::steady_clock::now();

        auto it = routes_.find(sensor_id);
        if (it == routes_.end())
        {
            res.verdict = SENTINEL_VERDICT_PASS;
            return res;
        }

        // Infer port from packet transport bytes or default
        uint16_t target_port = 502; // default heuristic for Modbus/SCADA evaluation
        if (packet.length >= 8 && packet.data[2] == 0x00 && packet.data[3] == 0x00)
        {
            target_port = 502;
        }
        else if (packet.length >= 4 && packet.data[0] == 0x03)
        {
            target_port = 102; // S7Comm TPKT
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
        if (spkg_res.verdict == SENTINEL_VERDICT_KERNEL_DROP)
        {
            // FAST-PATH SHORT-CIRCUIT: Terminate pipeline immediately!
            res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
            res.mitigated_by_stage = "SPKG_REFLEX_GATE";
            res.rule_or_model_id = spkg_res.threat_name;
            res.anomaly_score = 1.0f;
            res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       std::chrono::steady_clock::now() - t_start)
                                       .count();
            return res;
        }

        // -------------------------------------------------------------------------
        // STAGE 2 & 3: SUBSYSTEM & SILICON MODEL CHAIN (libxinfer.so simulation)
        // -------------------------------------------------------------------------
        for (const auto &stage : rule->model_stages)
        {
            // Emulate neural inference across hardware target (Intel NPU / NVIDIA GPU)
            float score = 0.15f; // Baseline benign score

            // If packet contains anomalous physical parameters, trigger model anomaly
            if (packet.length >= 8 && packet.data[7] == 0x05)
            {
                score = 0.94f; // Breaches threshold_drop (0.88)
            }

            if (score >= stage.threshold_drop)
            {
                res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                res.mitigated_by_stage = "SUBSYSTEM_" + rule->owner_subsystem;
                res.rule_or_model_id = stage.model_id + " [" + stage.silicon_target + "]";
                res.anomaly_score = score;
                res.mrd_xai_attribution = "SCADA_Function_Code (54.2%) | Physical_Actuator_Zone (28.1%)";
                res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           std::chrono::steady_clock::now() - t_start)
                                           .count();
                return res; // Short-circuit on model threshold breach!
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

        for (const auto &rule : fusion_rules_)
        {
            // Stuxnet HMI Discrepancy Detection:
            // Cyber says normal (low score) BUT physical sensor says overheating (> 120°C)
            if (rule.cyber_sensor_id == cyber_sensor_id &&
                rule.physical_sensor_id == physical_sensor_id)
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