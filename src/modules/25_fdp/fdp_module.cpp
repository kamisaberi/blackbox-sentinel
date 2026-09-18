#include "fdp_module.hpp"
#include <iostream>

namespace sentinel::modules::fdp {

FdpModule::FdpModule()
    : graph_(std::make_unique<TransactionGraph>()),
      id_filter_(std::make_unique<SyntheticIDFilter>()) {}

bool FdpModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 25] FDP Financial Fraud & Transaction Graph Engine initialized." << std::endl;
    return true;
}

bool FdpModule::start() {
    running_ = true;
    std::cout << "[Module 25] FDP Financial Fraud & Transaction Graph Engine started." << std::endl;
    return true;
}

void FdpModule::stop() {
    running_ = false;
    std::cout << "[Module 25] FDP Financial Fraud & Transaction Graph Engine stopped." << std::endl;
}

void FdpModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    if (event.description.find("FINANCIAL_TRANSACTION") != std::string::npos) {
        double amount = event.features.size() > 0 ? event.features[0] * 50000.0 : 1000.0;
        graph_->add_edge(event.source_ip, event.destination_ip, amount);

        if (graph_->detect_circular_muling(event.source_ip)) {
            event.anomaly_score = 0.99f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [FDP Alert: Circular Money Muling Ring Intercepted]";
        }

        float synth_risk = id_filter_->evaluate_synthetic_risk(event.features);
        if (synth_risk > 0.85f) {
            event.anomaly_score = std::max(event.anomaly_score, synth_risk);
            event.description += " [FDP Alert: Synthetic Identity Profile Manipulation]";
        }
    }
}

bool FdpModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::fdp