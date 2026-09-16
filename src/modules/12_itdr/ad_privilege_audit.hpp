#pragma once

#include <string>
#include <unordered_set>
#include <mutex>

namespace sentinel::modules::itdr {

class ADPrivilegeAudit {
public:
    ADPrivilegeAudit();
    ~ADPrivilegeAudit() = default;

    bool audit_event(uint32_t event_id, const std::string& target_group, const std::string& member_name, std::string& out_alert);

private:
    std::unordered_set<std::string> critical_groups_;
    std::mutex audit_mutex_;
};

} // namespace sentinel::modules::itdr