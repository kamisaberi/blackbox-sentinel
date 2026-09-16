#include "cwpp_module.hpp"
#include <iostream>

namespace sentinel::modules::cwpp {

CwppModule::CwppModule()
    : evaluator_(std::make_unique<SyscallEvaluator>()),
      watcher_(std::make_unique<ContainerWatcher>()) {}

bool CwppModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 09] CWPP Container eBPF Syscall Guard initialized." << std::endl;
    return true;
}

bool CwppModule::start() {
    running_ = true;
    std::cout << "[Module 09] CWPP Container eBPF Syscall Guard started." << std::endl;
    return true;
}

void CwppModule::stop() {
    running_ = false;
    std::cout << "[Module 09] CWPP Container eBPF Syscall Guard stopped." << std::endl;
}

void CwppModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("CONTAINER_SYSCALL") != std::string::npos) {
        // Map feature floats to simulated syscall IDs
        std::vector<uint32_t> syscall_seq;
        for (float f : event.features) {
            syscall_seq.push_back(static_cast<uint32_t>(f * 400.0f));
        }

        std::string threat_details;
        float score = evaluator_->evaluate_sequence(syscall_seq, threat_details);

        if (score >= 0.85f) {
            event.anomaly_score = std::max(event.anomaly_score, score);
            event.level = blackbox::ThreatLevel::Critical;
            event.action_taken = blackbox::ActionType::KillProcess;
            event.description += " [CWPP Alert: " + threat_details + "]";
        }
    }
}

bool CwppModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::cwpp