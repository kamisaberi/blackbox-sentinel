#pragma once

#include "sentinel/module_interface.hpp"
#include "prompt_sanitizer.hpp"
#include "data_leak_guard.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::ai_trism {

class AiTrismModule : public ISentinelModule {
public:
    AiTrismModule();
    ~AiTrismModule() override = default;

    ModuleID get_id() const override { return ModuleID::AI_TRISM; }
    const char* get_name() const override { return "23_ai_trism"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<PromptSanitizer> prompt_sanitizer_;
    std::unique_ptr<DataLeakGuard> leak_guard_;
};

} // namespace sentinel::modules::ai_trism