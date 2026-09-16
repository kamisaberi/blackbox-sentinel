#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace sentinel::modules::cwpp {

class SyscallEvaluator {
public:
    SyscallEvaluator() = default;
    ~SyscallEvaluator() = default;

    // Analyzes sequence of Linux syscall numbers (e.g. ptrace, bpf, setns, unshare)
    float evaluate_sequence(const std::vector<uint32_t>& syscall_sequence, std::string& out_threat);
};

} // namespace sentinel::modules::cwpp