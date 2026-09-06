#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace sentinel::modules::cps_sec {

struct ModbusFrame {
    uint16_t transaction_id{0};
    uint16_t protocol_id{0};
    uint16_t length{0};
    uint8_t unit_id{0};
    uint8_t function_code{0};
    uint16_t reference_address{0};
    uint16_t value_or_count{0};
    bool valid{false};
};

class ModbusParser {
public:
    ModbusParser() = default;
    ~ModbusParser() = default;

    ModbusFrame parse_mbap(const uint8_t* raw_bytes, size_t size);
    bool is_write_function(uint8_t function_code);
};

} // namespace sentinel::modules::cps_sec