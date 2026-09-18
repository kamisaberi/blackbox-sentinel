#pragma once

#include <string>
#include <unordered_set>
#include <mutex>

namespace sentinel::modules::ddp {

class HoneyTokenMonitor {
public:
    HoneyTokenMonitor();
    ~HoneyTokenMonitor() = default;

    bool check_token_access(const std::string& accessed_token, std::string& out_alert);

private:
    std::unordered_set<std::string> honey_tokens_;
    std::mutex token_mutex_;
};

} // namespace sentinel::modules::ddp