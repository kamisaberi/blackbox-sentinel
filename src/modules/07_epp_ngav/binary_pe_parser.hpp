#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace sentinel::modules::epp_ngav {

class BinaryPEParser {
public:
    BinaryPEParser() = default;
    ~BinaryPEParser() = default;

    bool inspect_binary_header(const uint8_t* header_data, size_t size, std::string& out_finding);
};

} // namespace sentinel::modules::epp_ngav