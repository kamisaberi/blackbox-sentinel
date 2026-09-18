#include "ai_trism_module.hpp"
#include <iostream>

namespace sentinel::modules::ai_trism {

AiTrismModule::AiTrismModule()
    : prompt_sanitizer_(std::make_unique<PromptSanitizer>()),
      leak_guard_(std::make_unique<DataLeakGuard>()) {}

bool AiTrismModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 23] AI TRiSM Prompt Firewall & Data Leak Guard initialized." << std::endl;
    return true;
}

bool AiTrismModule::start() {
    running_ = true;
    std::cout << "[Module 23] AI TRiSM Prompt Firewall & Data Leak Guard started." << std::endl;
    return true;
}

void AiTrismModule::stop() {
    running_ = false;
    std::cout << "[Module 23] AI TRiSM Prompt Firewall & Data Leak Guard stopped." << std::endl;
}

void AiTrismModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("LLM_PROMPT") != std::string::npos) {
        std::string attack_type;
        if (prompt_sanitizer_->is_jailbreak_attempt(event.description, attack_type)) {
            event.anomaly_score = 0.99f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [AI TRiSM Alert: " + attack_type + "]";
        }

        std::string leak_type;
        if (leak_guard_->detect_data_leak(event.description, leak_type)) {
            event.anomaly_score = 0.95f;
            event.level = blackbox::ThreatLevel::High;
            event.description += " [AI TRiSM Alert: " + leak_type + "]";
        }
    }
}

bool AiTrismModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ai_trism