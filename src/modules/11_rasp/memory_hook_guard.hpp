#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace sentinel::modules::rasp {

class MemoryHookGuard {
public:
    MemoryHookGuard() = default;
    ~MemoryHookGuard() = default;

    // Checks function prologue bytes for in-memory detours (e.g. 0xE9 JMP patches)
    bool detect_function_hook(const void* function_ptr, size_t prologue_bytes_to_check = 5);
};

} // namespace sentinel::modules::rasp