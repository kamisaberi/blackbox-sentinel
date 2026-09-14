#pragma once

#include <cstdint>
#include <string>

namespace sentinel::modules::edr {

class MemoryScanner {
public:
    MemoryScanner() = default;
    ~MemoryScanner() = default;

    // Checks /proc/<pid>/maps for unmapped executable memory segments (Beaconing / Shellcode)
    bool scan_pid_for_injection(uint32_t pid, std::string& out_details);
};

} // namespace sentinel::modules::edr