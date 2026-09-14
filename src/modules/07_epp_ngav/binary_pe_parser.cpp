#include "binary_pe_parser.hpp"
#include <cstring>

namespace sentinel::modules::epp_ngav {

bool BinaryPEParser::inspect_binary_header(const uint8_t* header_data, size_t size, std::string& out_finding) {
    if (!header_data || size < 64) return false;

    // Check for ELF Magic (\x7fELF)
    if (header_data[0] == 0x7f && header_data[1] == 'E' && header_data[2] == 'L' && header_data[3] == 'F') {
        out_finding = "Executable ELF Binary Identified";
        return true;
    }

    // Check for DOS MZ Magic
    if (header_data[0] == 'M' && header_data[1] == 'Z') {
        out_finding = "Portable Executable (PE/MZ) Binary Identified";
        return true;
    }

    return false;
}

} // namespace sentinel::modules::epp_ngav