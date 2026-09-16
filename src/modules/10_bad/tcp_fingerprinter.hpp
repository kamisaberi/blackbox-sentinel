#pragma once

#include <cstdint>
#include <string>

namespace sentinel::modules::bad {

class TCPFingerprinter {
public:
    TCPFingerprinter() = default;
    ~TCPFingerprinter() = default;

    // Evaluates SYN packet MSS, Window Size, and TCP Options ordering (p0f/JA4T heuristic)
    bool is_automated_scanner(uint16_t window_size, uint16_t mss, uint8_t ttl);
};

} // namespace sentinel::modules::bad