#include "waf_module.hpp"
#include <iostream>

namespace sentinel::modules::waf {

WafModule::WafModule()
    : payload_evaluator_(std::make_unique<HTTPPayloadEvaluator>()),
      logic_inspector_(std::make_unique<APILogicInspector>()) {}

bool WafModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 05] WAF Web App & API Defense Engine initialized." << std::endl;
    return true;
}

bool WafModule::start() {
    running_ = true;
    std::cout << "[Module 05] WAF Web App & API Defense Engine started." << std::endl;
    return true;
}

void WafModule::stop() {
    running_ = false;
    std::cout << "[Module 05] WAF Web App & API Defense Engine stopped." << std::endl;
}

void WafModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Evaluate HTTP payload if present in description or features
    float sqli_score = payload_evaluator_->evaluate_sqli(event.description);
    float xss_score = payload_evaluator_->evaluate_xss(event.description);
    float cmd_score = payload_evaluator_->evaluate_command_injection(event.description);
    bool traversal = logic_inspector_->detect_path_traversal(event.description);

    float max_waf_score = std::max({sqli_score, xss_score, cmd_score, traversal ? 0.95f : 0.0f});

    if (max_waf_score >= 0.85f) {
        event.anomaly_score = std::max(event.anomaly_score, max_waf_score);
        event.level = blackbox::ThreatLevel::Critical;
        event.action_taken = blackbox::ActionType::EBPFBlockIP;
        event.description += " [WAF Block: Web Application / API Attack Vector]";
    }
}

bool WafModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::waf