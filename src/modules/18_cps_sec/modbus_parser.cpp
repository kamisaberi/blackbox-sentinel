#include "modbus_parser.hpp"
#include <arpa/inet.h>

namespace sentinel::modules::cps_sec {

ModbusFrame ModbusParser::parse_mbap(const uint8_t* raw_bytes, size_t size) {
    ModbusFrame f;
    // MBAP header is 7 bytes minimum + PDU function code
    if (!raw_bytes || size < 8) return f;

    f.transaction_id = ntohs(*reinterpret_cast<const uint16_t*>(raw_bytes + 0));
    f.protocol_id    = ntohs(*reinterpret_cast<const uint16_t*>(raw_bytes + 2));
    f.length         = ntohs(*reinterpret_cast<const uint16_t*>(raw_bytes + 4));
    f.unit_id        = raw_bytes[6];
    f.function_code  = raw_bytes[7];

    if (size >= 12) {
        f.reference_address = ntohs(*reinterpret_cast<const uint16_t*>(raw_bytes + 8));
        f.value_or_count    = ntohs(*reinterpret_cast<const uint16_t*>(raw_bytes + 10));
    }

    f.valid = (f.protocol_id == 0x0000); // Protocol ID must be 0 for Modbus TCP
    return f;
}

bool ModbusParser::is_write_function(uint8_t fc) {
    // Write Single Coil (0x05), Write Single Register (0x06), Write Multiple Coils (0x0F), Write Multiple Registers (0x10)
    return (fc == 0x05 || fc == 0x06 || fc == 0x0F || fc == 0x10);
}

} // namespace sentinel::modules::cps_sec