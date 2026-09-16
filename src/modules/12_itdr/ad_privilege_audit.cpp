#include "ad_privilege_audit.hpp"
#include <algorithm>

namespace sentinel::modules::itdr {

ADPrivilegeAudit::ADPrivilegeAudit() {
    critical_groups_.insert("DOMAIN ADMINS");
    critical_groups_.insert("ENTERPRISE ADMINS");
    critical_groups_.insert("SCHEMA ADMINS");
    critical_groups_.insert("ADMINISTRATORS");
    critical_groups_.insert("BACKUP OPERATORS");
}

bool ADPrivilegeAudit::audit_event(uint32_t event_id, const std::string& target_group, const std::string& member_name, std::string& out_alert) {
    std::string grp_upper = target_group;
    std::transform(grp_upper.begin(), grp_upper.end(), grp_upper.begin(), ::toupper);

    // Event 4728: Member added to security-enabled global group
    // Event 4732: Member added to security-enabled local group
    // Event 4756: Member added to security-enabled universal group
    if (event_id == 4728 || event_id == 4732 || event_id == 4756) {
        std::lock_guard<std::mutex> lock(audit_mutex_);
        if (critical_groups_.find(grp_upper) != critical_groups_.end()) {
            out_alert = "Critical privilege escalation: user " + member_name + " added to sensitive group " + target_group;
            return true;
        }
    }

    // Event 4672: Special privileges assigned to new logon
    if (event_id == 4672 && (member_name.find("admin") != std::string::npos || member_name.find("root") != std::string::npos)) {
        out_alert = "Sensitive administrator privilege logon assigned: " + member_name;
        return true;
    }

    return false;
}

} // namespace sentinel::modules::itdr