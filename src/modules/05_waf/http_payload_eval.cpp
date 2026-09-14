#include "http_payload_eval.hpp"
#include <algorithm>

namespace sentinel::modules::waf {

static std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

float HTTPPayloadEvaluator::evaluate_sqli(const std::string& payload) {
    if (payload.empty()) return 0.0f;
    std::string p = to_lower_copy(payload);

    if (p.find("' or '1'='1") != std::string::npos ||
        p.find("' or 1=1") != std::string::npos ||
        p.find("union select") != std::string::npos ||
        p.find("drop table") != std::string::npos ||
        p.find("--") != std::string::npos) {
        return 0.98f;
    }
    return 0.05f;
}

float HTTPPayloadEvaluator::evaluate_xss(const std::string& payload) {
    if (payload.empty()) return 0.0f;
    std::string p = to_lower_copy(payload);

    if (p.find("<script>") != std::string::npos ||
        p.find("javascript:") != std::string::npos ||
        p.find("onerror=") != std::string::npos ||
        p.find("onload=") != std::string::npos ||
        p.find("<img src=x") != std::string::npos) {
        return 0.95f;
    }
    return 0.05f;
}

float HTTPPayloadEvaluator::evaluate_command_injection(const std::string& payload) {
    if (payload.empty()) return 0.0f;

    if (payload.find("; cat /etc/passwd") != std::string::npos ||
        payload.find("| nc ") != std::string::npos ||
        payload.find("; id;") != std::string::npos ||
        payload.find("&& whoami") != std::string::npos ||
        payload.find("$(curl") != std::string::npos) {
        return 0.99f;
    }
    return 0.05f;
}

} // namespace sentinel::modules::waf