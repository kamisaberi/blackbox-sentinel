#include "ueba_module.hpp"
#include <iostream>

namespace sentinel::modules::ueba {

UebaModule::UebaModule()
    : matrix_(std::make_unique<BehaviorMatrix>()),
      scorer_(std::make_unique<BaselineScorer>()) {}

bool UebaModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 02] UEBA Behavioral Analytics Engine initialized." << std::endl;
    return true;
}

bool UebaModule::start() {
    running_ = true;
    std::cout << "[Module 02] UEBA Behavioral Analytics Engine started." << std::endl;
    return true;
}

void UebaModule::stop() {
    running_ = false;
    std::cout << "[Module 02] UEBA Behavioral Analytics Engine stopped." << std::endl;
}

void UebaModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_ || event.source_ip.empty()) return;

    // Use source IP as actor identity
    std::string actor_id = event.source_ip;
    double bytes = !event.features.empty() ? event.features[0] * 1500.0 : 512.0;

    // Simulate off-hours flag based on event time
    auto time_t_now = std::chrono::system_clock::to_time_t(event.timestamp);
    struct tm gmt_buf{};
    gmtime_r(&time_t_now, &gmt_buf);
    bool is_off_hours = (gmt_buf.tm_hour < 6 || gmt_buf.tm_hour > 20);

    auto profile = matrix_->get_profile(actor_id);
    float ueba_anomaly = scorer_->calculate_anomaly(profile, bytes, is_off_hours);

    matrix_->update_user(actor_id, bytes, is_off_hours);

    if (ueba_anomaly >= 0.70f) {
        event.anomaly_score = std::max(event.anomaly_score, ueba_anomaly);
        event.description += " [UEBA Anomaly: Behavioral Deviation]";
    }
}

bool UebaModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::ueba