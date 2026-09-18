#pragma once

#include <string>
#include <vector>

namespace sentinel::modules::ai_trism {

class DataLeakGuard {
public:
    DataLeakGuard();
    ~DataLeakGuard() = default;

    bool detect_data_leak(const std::string& llm_output_text, std::string& out_finding);

private:
    std::vector<std::pair<std::string, std::string>> secret_patterns_;
};

} // namespace sentinel::modules::ai_trism