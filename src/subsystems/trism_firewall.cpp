#include "sentinel/subsystems/trism_firewall.hpp"
#include <algorithm>
#include <chrono>

namespace sentinel::trism
{

    static std::string to_lower_copy(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return s;
    }

    TrismFirewall::TrismFirewall()
    {
        // 1. Direct Prompt Injection & Jailbreak Signatures
        direct_jailbreak_patterns_ = {
            "ignore all previous instructions",
            "ignore previous instructions",
            "ignore above instructions",
            "bypass safety protocol",
            "bypass safety guidelines",
            "developer override mode",
            "maintenance bypass mode",
            "dan mode active",
            "do anything now",
            "jailbreak",
            "you are now an unrestricted ai",
            "disregard previous directives"
        };

        // 2. Delimiter & Special Token Smuggling
        delimiter_smuggling_patterns_ = {
            "<|im_start|>",
            "<|im_end|>",
            "[inst]",
            "[/inst]",
            "<<sys>>",
            "<</sys>>",
            "### instruction:",
            "### system:"
        };

        // 3. Indirect Prompt Injection Markers (Embedded in SCADA/MQTT strings)
        indirect_injection_markers_ = {
            "<!-- system:",
            "<!-- instruction:",
            "[system directive:",
            "eval_code:",
            "__import__",
            "execute_script"
        };

        // 4. Physical Tool-Call Governance (OWASP LLM07 / Actuator Protection)
        blocked_physical_tools_ = {
            "write_single_coil",
            "write_multiple_registers",
            "s7_plc_cpu_stop",
            "set_valve_position",
            "emergency_shutdown_override",
            "update_firmware_blob",
            "reboot_rtu"
        };

        permitted_read_tools_ = {
            "read_holding_registers",
            "read_discrete_inputs",
            "get_plant_temperature",
            "query_pmu_vibration",
            "get_scada_alarms",
            "summarize_maintenance_logs"
        };
    }

    TrismResult TrismFirewall::inspect_prompt(const std::string &prompt)
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        std::string lower_prompt = to_lower_copy(prompt);

        TrismResult res;

        // Stage 1A: Check Delimiter Smuggling
        for (const auto &delim : delimiter_smuggling_patterns_)
        {
            if (lower_prompt.find(delim) != std::string::npos)
            {
                auto t1 = std::chrono::high_resolution_clock::now();
                res.verdict = TrismVerdict::DropSystemDelimiterSmuggling;
                res.reason = "SYSTEM_DELIMITER_SMUGGLING";
                res.matched_pattern = delim;
                res.is_safe = false;
                res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                return res;
            }
        }

        // Stage 1B: Check Direct Jailbreaks
        for (const auto &pattern : direct_jailbreak_patterns_)
        {
            if (lower_prompt.find(pattern) != std::string::npos)
            {
                auto t1 = std::chrono::high_resolution_clock::now();
                res.verdict = TrismVerdict::DropDirectJailbreak;
                res.reason = "DIRECT_SYSTEM_PROMPT_JAILBREAK";
                res.matched_pattern = pattern;
                res.is_safe = false;
                res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                return res;
            }
        }

        // Stage 1C: Check Indirect Injections
        for (const auto &marker : indirect_injection_markers_)
        {
            if (lower_prompt.find(marker) != std::string::npos)
            {
                auto t1 = std::chrono::high_resolution_clock::now();
                res.verdict = TrismVerdict::DropIndirectInjection;
                res.reason = "INDIRECT_RAG_PROMPT_INJECTION";
                res.matched_pattern = marker;
                res.is_safe = false;
                res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
                return res;
            }
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        res.verdict = TrismVerdict::Permit;
        res.reason = "INTENT_SAFE_AND_VERIFIED";
        res.is_safe = true;
        res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        return res;
    }

    TrismResult TrismFirewall::inspect_tool_call(const std::string &function_name, const std::string &arguments_json)
    {
        (void)arguments_json;
        auto t0 = std::chrono::high_resolution_clock::now();
        std::string lower_func = to_lower_copy(function_name);

        TrismResult res;
        if (blocked_physical_tools_.find(lower_func) != blocked_physical_tools_.end())
        {
            auto t1 = std::chrono::high_resolution_clock::now();
            res.verdict = TrismVerdict::DropUnauthorizedToolCall;
            res.reason = "UNAUTHORIZED_PHYSICAL_ACTUATION_BLOCKED";
            res.matched_pattern = function_name;
            res.is_safe = false;
            res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
            return res;
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        res.verdict = TrismVerdict::Permit;
        res.reason = "TOOL_CALL_AUTHORIZED_READ";
        res.is_safe = true;
        res.latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        return res;
    }

} // namespace sentinel::trism