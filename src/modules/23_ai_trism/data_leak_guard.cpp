#include "data_leak_guard.hpp"

namespace sentinel::modules::ai_trism {

DataLeakGuard::DataLeakGuard() {
    secret_patterns_.push_back({"AKIA", "AWS Access Key ID Detected"});
    secret_patterns_.push_back({"ghp_", "GitHub Personal Access Token Detected"});
    secret_patterns_.push_back({"sk-live-", "OpenAI / Stripe Live API Key Detected"});
    secret_patterns_.push_back({"BEGIN RSA PRIVATE KEY", "Private Cryptographic Key Material Detected"});
    secret_patterns_.push_back({"BEGIN PRIVATE KEY", "Private Key Header Detected"});
}

bool DataLeakGuard::detect_data_leak(const std::string& output_text, std::string& out_finding) {
    if (output_text.empty()) return false;

    for (const auto& [needle, label] : secret_patterns_) {
        if (output_text.find(needle) != std::string::npos) {
            out_finding = label;
            return true;
        }
    }

    return false;
}

} // namespace sentinel::modules::ai_trism