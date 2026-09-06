#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace sentinel::modules::cdr {

struct SanitizationResult {
    bool malicious_elements_found{false};
    size_t stripped_objects_count{0};
    std::vector<std::string> threat_details;
    std::vector<uint8_t> clean_buffer;
};

class PDFSanitizer {
public:
    PDFSanitizer() = default;
    ~PDFSanitizer() = default;

    SanitizationResult sanitize_pdf_stream(const uint8_t* raw_bytes, size_t size);
};

} // namespace sentinel::modules::cdr