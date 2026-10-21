#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <chrono>

namespace sentinel::trism
{

    enum class TrismVerdict : uint32_t
    {
        Permit = 0,
        DropDirectJailbreak = 1,
        DropIndirectInjection = 2,
        DropUnauthorizedToolCall = 3,
        DropSystemDelimiterSmuggling = 4
    };

    struct TrismResult
    {
        TrismVerdict verdict{TrismVerdict::Permit};
        std::string reason;
        std::string matched_pattern;
        uint64_t latency_ns{0};
        bool is_safe{true};
    };

    class TrismFirewall
    {
    public:
        TrismFirewall();
        TrismResult inspect_prompt(const std::string &prompt);
        TrismResult inspect_tool_call(const std::string &function_name, const std::string &arguments_json = "{}");

    private:
        std::vector<std::string> direct_jailbreak_patterns_;
        std::vector<std::string> delimiter_smuggling_patterns_;
        std::vector<std::string> indirect_injection_markers_;
        std::unordered_set<std::string> blocked_physical_tools_;
        std::unordered_set<std::string> permitted_read_tools_;
    };

} // namespace sentinel::trism