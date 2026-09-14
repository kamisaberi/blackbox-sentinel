#include "siem_module.hpp"
#include <iostream>

namespace sentinel::modules::siem {

SiemModule::SiemModule()
    : correlator_(std::make_unique<LogCorrelator>()),
      time_series_(std::make_unique<TimeSeriesEngine>(60)) {}

bool SiemModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 01] SIEM Core Log Correlation initialized." << std::endl;
    return true;
}

bool SiemModule::start() {
    running_ = true;
    std::cout << "[Module 01] SIEM Core Log Correlation started." << std::endl;
    return true;
}

void SiemModule::stop() {
    running_ = false;
    std::cout << "[Module 01] SIEM Core Log Correlation stopped." << std::endl;
}

void SiemModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    time_series_->register_event();

    if (time_series_->detect_spike(3.0)) {
        event.description += " [SIEM Alert: High Event Frequency Spike]";
    }

    correlator_->evaluate(event);
}

bool SiemModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::siem