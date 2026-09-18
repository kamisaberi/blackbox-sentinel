#include "microsegment_enforcer.hpp"

namespace sentinel::modules::ztna {

AccessTier MicrosegmentEnforcer::determine_tier(uint32_t trust_score) {
    if (trust_score >= 80) return AccessTier::FullAccess;
    if (trust_score >= 50) return AccessTier::RestrictedSubnet;
    if (trust_score >= 20) return AccessTier::QuarantineVLAN;
    return AccessTier::Revoked;
}

bool MicrosegmentEnforcer::enforce_policy(const std::string& device_id, uint32_t trust_score, std::string& out_action) {
    AccessTier tier = determine_tier(trust_score);

    switch (tier) {
        case AccessTier::FullAccess:
            out_action = "Tier 1: Full authorized perimeter access";
            return false; // No restriction
        case AccessTier::RestrictedSubnet:
            out_action = "Tier 2: Restricted to internal DMZ segment only";
            return true;
        case AccessTier::QuarantineVLAN:
            out_action = "Tier 3: Dynamic micro-segmentation quarantine enforced (VLAN 999)";
            return true;
        case AccessTier::Revoked:
            out_action = "Tier 4: Zero Trust access completely revoked; eBPF drop mandated";
            return true;
    }
    return false;
}

} // namespace sentinel::modules::ztna