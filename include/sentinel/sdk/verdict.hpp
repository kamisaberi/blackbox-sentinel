#pragma once

#include "abi.hpp"
#include <string_view>
#include <algorithm>
#include <cstring>

namespace sentinel::sdk {

class VerdictBuilder {
public:
    constexpr VerdictBuilder() noexcept {
        result_.verdict = SENTINEL_VERDICT_PASS;
        result_.threat_score = 0;
        result_.rule_id = 0;
        result_.semantic_tags = 0;
        result_.threat_name[0] = '\0';
    }

    static constexpr VerdictBuilder Pass() noexcept {
        return VerdictBuilder();
    }

    static VerdictBuilder Drop(uint32_t rule_id, std::string_view threat_name, float score = 1.0f) noexcept {
        VerdictBuilder b;
        b.result_.verdict = SENTINEL_VERDICT_KERNEL_DROP;
        b.result_.rule_id = rule_id;
        b.result_.threat_score = static_cast<uint32_t>(std::clamp(score, 0.0f, 1.0f) * 1000.0f);
        b.set_name(threat_name);
        return b;
    }

    static VerdictBuilder Alert(uint32_t rule_id, std::string_view threat_name, float score = 0.8f) noexcept {
        VerdictBuilder b;
        b.result_.verdict = SENTINEL_VERDICT_ALERT;
        b.result_.rule_id = rule_id;
        b.result_.threat_score = static_cast<uint32_t>(std::clamp(score, 0.0f, 1.0f) * 1000.0f);
        b.set_name(threat_name);
        return b;
    }

    static VerdictBuilder Honeypot(uint32_t rule_id, std::string_view threat_name) noexcept {
        VerdictBuilder b;
        b.result_.verdict = SENTINEL_VERDICT_HONEYPOT_DIVERT;
        b.result_.rule_id = rule_id;
        b.result_.threat_score = 900;
        b.set_name(threat_name);
        return b;
    }

    VerdictBuilder& with_tag(uint64_t tag) noexcept {
        result_.semantic_tags |= tag;
        return *this;
    }

    VerdictBuilder& with_tags(uint64_t tags) noexcept {
        result_.semantic_tags |= tags;
        return *this;
    }

    [[nodiscard]] constexpr SentinelDissectorResult build() const noexcept {
        return result_;
    }

    [[nodiscard]] constexpr operator SentinelDissectorResult() const noexcept {
        return result_;
    }

private:
    void set_name(std::string_view name) noexcept {
        size_t len = std::min(name.size(), sizeof(result_.threat_name) - 1);
        std::memcpy(result_.threat_name, name.data(), len);
        result_.threat_name[len] = '\0';
    }

    SentinelDissectorResult result_{};
};

} // namespace sentinel::sdk