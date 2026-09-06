#include "dnp3_parser.hpp"
#include <cstring>

namespace sentinel::modules::cps_sec {

DNP3Frame DNP3Parser::parse_header(const uint8_t* raw_bytes, size_t size) {
    DNP3Frame f;
    if (!raw_bytes || size < 10) return f;

    // DNP3 Sync pattern: 0x05 0x64
    if (raw_bytes[0] == 0x05 && raw_bytes[1] == 0x64) {
        f.sync_bytes   = 0x0564;
        f.length       = raw_bytes[2];
        f.link_control = raw_bytes[3];
        std::memcpy(&f.destination, raw_bytes + 4, 2);
        std::memcpy(&f.source, raw_bytes + 6, 2);
        
        if (size >= 13) {
            f.function_code = raw_bytes[12];
        }
        f.valid = true;
    }
    return f;
}

bool DNP3Parser::is_control_command(uint8_t fc) {
    // 0x03 = SELECT, 0x04 = OPERATE, 0x05 = DIRECT_OPERATE, 0x06 = DIRECT_OPERATE_NO_ACK
    return (fc >= 0x03 && fc <= 0x06);
}

} // namespace sentinel::modules::cps_sec