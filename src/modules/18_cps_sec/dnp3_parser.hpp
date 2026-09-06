#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace sentinel::modules::cps_sec {

struct DNP3Frame {
    uint16_t sync_bytes{0};
    uint8_t length{0};
    uint8_t link_control{0};
    uint16_t destination{0};
    uint16_t source{0};
    uint8_t function_code{0};
    bool valid{false};
};

class DNP3Parser {
public:
    DNP3Parser() = default;
    ~DNP3Parser() = default;

    DNP3Frame parse_header(const uint8_t* raw_bytes, size_t size);
    bool is_control_command(uint8_t function_code);
};

} // namespace sentinel::modules::cps_sec