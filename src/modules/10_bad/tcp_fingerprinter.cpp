#include "tcp_fingerprinter.hpp"

namespace sentinel::modules::bad {

bool TCPFingerprinter::is_automated_scanner(uint16_t window_size, uint16_t mss, uint8_t ttl) {
    // Exact signatures of automated scanning engines (ZMap, Masscan, Nmap default)
    if (window_size == 1024 && mss == 1460) {
        return true; // Typical raw SYN scan engine signature
    }

    if (window_size == 65535 && ttl == 255) {
        return true; // Scripted crawler stack
    }

    return false;
}

} // namespace sentinel::modules::bad