#pragma once

#include <blackbox/event.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace sentinel::modules::siem {

struct CorrelationRule {
    std::string rule_id;
    std::string name;
    float threshold;
    std::chrono::seconds time_window;
};

class LogCorrelator {
public:
    LogCorrelator();
    ~LogCorrelator() = default;

    void add_rule(const CorrelationRule& rule);
    bool evaluate(blackbox::SecurityEvent& event);

private:
    std::vector<CorrelationRule> rules_;
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> event_history_;
    std::mutex correlator_mutex_;
};

} // namespace sentinel::modules::siem