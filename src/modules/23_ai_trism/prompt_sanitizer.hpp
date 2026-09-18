#pragma once

#include <string>
#include <vector>

namespace sentinel::modules::ai_trism {

class PromptSanitizer {
public:
    PromptSanitizer();
    ~PromptSanitizer() = default;

    bool is_jailbreak_attempt(const std::string& input_prompt, std::string& out_attack_type);

private:
    std::vector<std::pair<std::string, std::string>> jailbreak_patterns_;
};

} // namespace sentinel::modules::ai_trism