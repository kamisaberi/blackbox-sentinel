#include "syscall_evaluator.hpp"
#include <algorithm>

namespace sentinel::modules::cwpp {

// Common Linux x86_64 Syscall Numbers
constexpr uint32_t SYS_PTRACE   = 101;
constexpr uint32_t SYS_SETNS    = 308;
constexpr uint32_t SYS_UNSHARE  = 272;
constexpr uint32_t SYS_BPF      = 321;
constexpr uint32_t SYS_MOUNT    = 165;

float SyscallEvaluator::evaluate_sequence(const std::vector<uint32_t>& seq, std::string& out_threat) {
    if (seq.empty()) return 0.0f;

    bool has_setns = false;
    bool has_unshare = false;
    bool has_ptrace = false;
    bool has_mount = false;

    for (uint32_t num : seq) {
        if (num == SYS_SETNS) has_setns = true;
        if (num == SYS_UNSHARE) has_unshare = true;
        if (num == SYS_PTRACE) has_ptrace = true;
        if (num == SYS_MOUNT) has_mount = true;
    }

    // Sequence heuristic: Container Breakout signature
    if (has_setns && has_mount) {
        out_threat = "Container Namespace Escape via setns() + mount()";
        return 0.99f;
    }

    if (has_unshare && has_ptrace) {
        out_threat = "Host Process Hijacking via unshare() + ptrace()";
        return 0.96f;
    }

    if (has_setns) {
        out_threat = "Unauthorized Namespace Transition attempt";
        return 0.85f;
    }

    return 0.05f;
}

} // namespace sentinel::modules::cwpp