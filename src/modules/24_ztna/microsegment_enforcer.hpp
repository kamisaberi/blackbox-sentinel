#pragma once

#include <string>
#include <cstdint>

namespace sentinel::modules::ztna {

enum class AccessTier {
    FullAccess,
    RestrictedSubnet,
    QuarantineVLAN,
    Revoked
};

class MicrosegmentEnforcer {
public:
    MicrosegmentEnforcer() = default;
    ~MicrosegmentEnforcer() = default;

    AccessTier determine_tier(uint32_t trust_score);
    bool enforce_policy(const std::string& device_id, uint32_t trust_score, std::string& out_action);
};

} // namespace sentinel::modules::ztna