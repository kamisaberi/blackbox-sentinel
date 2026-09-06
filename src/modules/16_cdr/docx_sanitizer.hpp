#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace sentinel::modules::cdr {

class DOCXSanitizer {
public:
    DOCXSanitizer() = default;
    ~DOCXSanitizer() = default;

    bool detect_vba_macros(const uint8_t* raw_bytes, size_t size, std::string& out_finding);
    bool detect_dde_exploit(const std::string& xml_content, std::string& out_finding);
};

} // namespace sentinel::modules::cdr