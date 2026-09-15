#include "log_correlator.hpp"
#include <algorithm>

namespace sentinel::modules::siem {

LogCorrelator::LogCorrelator() {
    // Default Core SIEM Correlation Rule
    rules_.push_back({
        "SIEM-RULE-001",
        "Multiple High Anomaly Log Bursts",
        0.80f,
        std::chrono::seconds(30)
    });
}

void LogCorrelator::add_rule(const CorrelationRule& rule) {
    std::lock_guard<std::mutex> lock(correlator_mutex_);
    rules_.push_back(rule);
}

bool LogCorrelator::evaluate(blackbox::SecurityEvent& event) {
    if (event.source_ip.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(correlator_mutex_);
    auto now = std::chrono::system_clock::now();
    auto& timestamps = event_history_[event.source_ip];

    // Clean up timestamps older than 60 seconds
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&](const auto& ts) {
                return (now - ts) > std::chrono::seconds(60);
            }),
        timestamps.end()
    );

    if (event.anomaly_score >= 0.70f) {
        timestamps.push_back(now);
    }

    // Check correlation rules
    for (const auto& rule : rules_) {
        if (event.anomaly_score >= rule.threshold) {
            size_t count = 0;
            for (const auto& ts : timestamps) {
                if ((now - ts) <= rule.time_window) {
                    count++;
                }
            }
            if (count >= 5) {
                event.description += " [SIEM Correlated: " + rule.name + "]";
                event.level = blackbox::ThreatLevel::Critical;
                return true;
            }
        }
    }
    return false;
}

} // namespace sentinel::modules::siem