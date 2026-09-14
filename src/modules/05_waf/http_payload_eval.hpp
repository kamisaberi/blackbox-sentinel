#pragma once

#include <string>
#include <vector>

namespace sentinel::modules::waf {

class HTTPPayloadEvaluator {
public:
    HTTPPayloadEvaluator() = default;
    ~HTTPPayloadEvaluator() = default;

    float evaluate_sqli(const std::string& payload);
    float evaluate_xss(const std::string& payload);
    float evaluate_command_injection(const std::string& payload);
};

} // namespace sentinel::modules::waf