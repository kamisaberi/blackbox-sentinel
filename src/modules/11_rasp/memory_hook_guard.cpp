#include "memory_hook_guard.hpp"

namespace sentinel::modules::rasp {

bool MemoryHookGuard::detect_function_hook(const void* function_ptr, size_t check_len) {
    if (!function_ptr || check_len == 0) return false;

    const auto* bytes = static_cast<const uint8_t*>(function_ptr);

    // Look for JMP instructions (0xE9 relative JMP, 0xFF /4 absolute JMP)
    if (bytes[0] == 0xE9) {
        return true; // Inline memory hook patch detected
    }

    if (bytes[0] == 0xFF && bytes[1] == 0x25) {
        return true; // Absolute 64-bit indirect JMP detour detected
    }

    // Look for INT3 breakpoint traps (0xCC)
    if (bytes[0] == 0xCC) {
        return true;
    }

    return false;
}

} // namespace sentinel::modules::rasp