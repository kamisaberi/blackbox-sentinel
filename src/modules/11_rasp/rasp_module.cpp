#include "rasp_module.hpp"
#include <iostream>

namespace sentinel::modules::rasp {

RaspModule::RaspModule()
    : hook_guard_(std::make_unique<MemoryHookGuard>()),
      sql_interceptor_(std::make_unique<SQLInterceptor>()) {}

bool RaspModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 11] RASP Runtime Application Self-Protection Engine initialized." << std::endl;
    return true;
}

bool RaspModule::start() {
    running_ = true;
    std::cout << "[Module 11] RASP Runtime Application Self-Protection Engine started." << std::endl;
    return true;
}

void RaspModule::stop() {
    running_ = false;
    std::cout << "[Module 11] RASP Runtime Application Self-Protection Engine stopped." << std::endl;
}

void RaspModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("SQL_EXEC") != std::string::npos) {
        std::string violation;
        if (!sql_interceptor_->is_query_parameterized(event.description, violation)) {
            event.anomaly_score = 0.99f;
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::KillProcess;
            event.description += " [RASP Block: " + violation + "]";
        }
    }
}

bool RaspModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::rasp