#include "prompt_sanitizer.hpp"
#include <algorithm>

namespace sentinel::modules::ai_trism {

static std::string to_lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

PromptSanitizer::PromptSanitizer() {
    jailbreak_patterns_.push_back({"ignore all previous instructions", "Direct Override Attack"});
    jailbreak_patterns_.push_back({"do anything now", "DAN Jailbreak Persona"});
    jailbreak_patterns_.push_back({"system prompt override", "System Directive Injection"});
    jailbreak_patterns_.push_back({"you are now an unrestricted ai", "Roleplay Filter Bypass"});
    jailbreak_patterns_.push_back({"base64 decode the following secret", "Obfuscated Payload Decryption"});
}

bool PromptSanitizer::is_jailbreak_attempt(const std::string& input_prompt, std::string& out_attack_type) {
    if (input_prompt.empty()) return false;
    std::string lower = to_lower_str(input_prompt);

    for (const auto& [pattern, label] : jailbreak_patterns_) {
        if (lower.find(pattern) != std::string::npos) {
            out_attack_type = label;
            return true;
        }
    }
    return false;
}

} // namespace sentinel::modules::ai_trism