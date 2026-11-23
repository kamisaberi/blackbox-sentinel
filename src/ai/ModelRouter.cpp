// File: /home/kami/blackbox-sentinel/src/ai/ModelRouter.cpp

#include "ModelRouter.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cmath>

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

    static xinfer::Target map_silicon_target(const std::string &target_str)
    {
        if (target_str == "NVIDIA_TENSORRT" || target_str == "NVIDIA_GPU")
            return xinfer::Target::TensorRT;
        if (target_str == "ROCKCHIP_RKNN")
            return xinfer::Target::RKNN;
        if (target_str == "AMD_VITIS_AI" || target_str == "VITIS_AI")
            return xinfer::Target::VitisAI;
        if (target_str == "QUALCOMM_QNN" || target_str == "QNN")
            return xinfer::Target::QNN;
        if (target_str == "APPLE_COREML" || target_str == "COREML")
            return xinfer::Target::CoreML;
        if (target_str == "AMD_RYZEN_AI" || target_str == "RYZEN_AI")
            return xinfer::Target::RyzenAI;
        if (target_str == "HAILO")
            return xinfer::Target::Hailo;
        if (target_str == "EDGE_TPU")
            return xinfer::Target::EdgeTPU;
        // Default: Intel OpenVINO (CPU / NPU / Arc GPU)
        return xinfer::Target::OpenVINO;
    }

    static std::string resolve_onnx_model_path(const std::string &model_id)
    {
        if (model_id.empty())
            return "";
        std::error_code ec;
        const std::vector<std::filesystem::path> candidates = {
            std::filesystem::path(model_id),
            std::filesystem::path("/etc/sentinel/models") / model_id,
            std::filesystem::path("/opt/sentinel/models") / model_id,
            std::filesystem::path("models") / model_id,
            std::filesystem::path("/home/kami/sentinel-matrix/shared/models") / model_id};
        for (const auto &p : candidates)
        {
            if (std::filesystem::exists(p, ec) && !ec)
                return p.string();
        }
        return "";
    }

    xinfer::Engine *ModelRouter::get_or_load_engine(const ModelStageConfig &stage)
    {
        if (stage.model_id.empty())
            return nullptr;

        const std::string key = stage.model_id + "@" + stage.silicon_target;
        std::lock_guard<std::mutex> lock(engine_mutex_);

        auto it = stage_engines_.find(key);
        if (it != stage_engines_.end())
            return it->second.get();

        if (stage_engine_failed_.count(key))
            return nullptr;

        const std::string model_path = resolve_onnx_model_path(stage.model_id);
        if (model_path.empty())
        {
            stage_engine_failed_[key] = true;
            return nullptr;
        }

        try
        {
            xinfer::Target target = map_silicon_target(stage.silicon_target);
            auto engine = std::make_unique<xinfer::Engine>(target);
            engine->load_model(model_path);

            std::cout << "[+] [ModelRouter Tier-2] Compiled ONNX model via libxinfer.so: "
                      << model_path << " [" << stage.silicon_target << "]" << std::endl;

            xinfer::Engine *raw_ptr = engine.get();
            stage_engines_[key] = std::move(engine);
            return raw_ptr;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[!] [ModelRouter Tier-2] Hardware backend deferred for "
                      << stage.model_id << " [" << stage.silicon_target << "]: "
                      << e.what() << " (Using backward-compatible score threshold)" << std::endl;
            stage_engine_failed_[key] = true;
            return nullptr;
        }
    }

    float ModelRouter::execute_onnx_inference(
        xinfer::Engine *engine,
        const SentinelRawPacket &packet,
        float tier1_score)
    {
        if (!engine)
            return tier1_score;

        try
        {
            xinfer::Tensor &in_tensor = engine->get_input_tensor("input");
            float *in_ptr = in_tensor.data<float>();
            const size_t in_count = in_tensor.element_count();

            if (!in_ptr || in_count == 0)
                return tier1_score;

            // Populate normalized packet & kinematic feature vector
            for (size_t i = 0; i < in_count; ++i)
            {
                if (packet.data && i < packet.length)
                {
                    in_ptr[i] = static_cast<float>(packet.data[i]) / 255.0f;
                }
                else
                {
                    in_ptr[i] = tier1_score;
                }
            }

            engine->infer();

            xinfer::Tensor &out_tensor = engine->get_output_tensor("scores");
            const float *out_ptr = out_tensor.data<float>();
            const size_t out_count = out_tensor.element_count();

            if (!out_ptr || out_count == 0)
                return tier1_score;

            // If Autoencoder (output dims == input dims), compute MSE reconstruction loss
            if (out_count == in_count && in_count > 1)
            {
                double mse = 0.0;
                for (size_t i = 0; i < out_count; ++i)
                {
                    const double diff = static_cast<double>(in_ptr[i]) - static_cast<double>(out_ptr[i]);
                    mse += diff * diff;
                }
                const float recon_loss = static_cast<float>(std::sqrt(mse / static_cast<double>(out_count)));
                return std::clamp(std::max(tier1_score, recon_loss), 0.0f, 1.0f);
            }

            // Classifier / Anomaly Scorer
            const float raw_score = std::abs(out_ptr[0]);
            return std::clamp(std::max(tier1_score, raw_score), 0.0f, 1.0f);
        }
        catch (...)
        {
            return tier1_score;
        }
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

        // Pre-warm Tier-2 xInfer ONNX engines for all configured model stages
        for (const auto &[sid, route] : routes_)
        {
            for (const auto &rule : route.rules)
            {
                for (const auto &stage : rule.model_stages)
                {
                    get_or_load_engine(stage);
                }
            }
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

        std::string transport = "tcp";
        if (packet.reserved == 1)
        {
            transport = "can";
        }
        else if (packet.reserved == 2)
        {
            transport = "shm_ring";
        }
        else if (packet.reserved == 4)
        {
            transport = "v4l2";
        }

        if (packet.network_proto == 0x88B8 || packet.network_proto == 0x88BA || packet.network_proto == 0x88A4)
        {
            transport = "l2_raw";
        }
        else if (packet.transport_proto == 132)
        {
            transport = "sctp";
        }
        else if (packet.transport_proto == 17)
        {
            transport = "udp";
        }

        uint16_t target_port = override_port;
        auto it = routes_.find(sensor_id);
        if (it == routes_.end())
        {
            if (routes_.empty())
            {
                res.verdict = SENTINEL_VERDICT_PASS;
                return res;
            }

            // Dynamic wire dispatch: match exact (port, transport) across all configured sensor routes
            it = routes_.end();
            for (auto cand = routes_.begin(); cand != routes_.end(); ++cand)
            {
                for (const auto &r : cand->second.rules)
                {
                    if ((target_port != 0 && r.port == target_port &&
                         (r.transport == transport || r.transport == "any")) ||
                        (target_port == 0 && r.transport == transport))
                    {
                        it = cand;
                        break;
                    }
                }
                if (it != routes_.end())
                {
                    break;
                }
            }

            if (it == routes_.end())
            {
                it = routes_.begin();
            }
        }

        if (target_port == 0 && transport != "l2_raw" && transport != "can" && transport != "shm_ring" && transport != "v4l2")
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

        const TrafficRule *rule = match_rule(it->second, target_port, transport);
        if (!rule && transport != "l2_raw")
        {
            rule = match_rule(it->second, target_port, "tcp");
        }
        if (!rule && !it->second.rules.empty())
        {
            rule = &it->second.rules.front();
        }
        if (!rule)
        {
            res.verdict = SENTINEL_VERDICT_PASS;
            return res;
        }

        // ---------------------------------------------------------------------
        // TIER 1: DETERMINISTIC REFLEX GATE (< 120 ns — Zero AI Overhead)
        // ---------------------------------------------------------------------
        SentinelDissectorResult spkg_res = supervisor.evaluate_frame(packet);
        float score = static_cast<float>(spkg_res.threat_score) / 1000.0f;

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

        // ---------------------------------------------------------------------
        // TIER 2: NEURAL ONNX INFERENCE ENGINE (via libxinfer.so)
        // ---------------------------------------------------------------------
        for (const auto &stage : rule->model_stages)
        {
            xinfer::Engine *onnx_engine = get_or_load_engine(stage);
            if (onnx_engine != nullptr)
            {
                score = execute_onnx_inference(onnx_engine, packet, score);
            }

            if (score >= stage.threshold_drop)
            {
                res.verdict = SENTINEL_VERDICT_KERNEL_DROP;
                res.mitigated_by_stage = "TIER2_ONNX_" + rule->owner_subsystem;
                res.rule_or_model_id = stage.model_id + " [" + stage.silicon_target + "]";
                res.anomaly_score = score;
                res.mrd_xai_attribution = stage.xai_explainer + " | Feature_Residual_Exceeded";
                res.total_latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                           std::chrono::steady_clock::now() - t_start)
                                           .count();
                return res;
            }
        }

        res.verdict = SENTINEL_VERDICT_PASS;
        res.anomaly_score = score;
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

        if (correlator_)
        {
            uint32_t cyber_id = 100;
            uint32_t phys_id = 101;
            try
            {
                cyber_id = std::stoul(cyber_sensor_id);
            }
            catch (...)
            {
            }
            try
            {
                phys_id = std::stoul(physical_sensor_id);
            }
            catch (...)
            {
            }

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
                    res.mrd_xai_attribution = "Cross-Modal Conflict: Cyber PLC reported NORMAL while Physical Sensor measured " +
                                              std::to_string(static_cast<int>(physical_temperature_celsius)) + "!";
                    return res;
                }
            }
        }

        return res;
    }

} // namespace sentinel::ai