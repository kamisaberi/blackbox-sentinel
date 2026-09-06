#include "pdf_sanitizer.hpp"
#include <cstring>
#include <algorithm>

namespace sentinel::modules::cdr {

SanitizationResult PDFSanitizer::sanitize_pdf_stream(const uint8_t* raw_bytes, size_t size) {
    SanitizationResult result;
    if (!raw_bytes || size < 8) return result;

    std::string content(reinterpret_cast<const char*>(raw_bytes), size);

    // Known weaponized PDF object keys
    const std::vector<std::pair<std::string, std::string>> dangerous_tags = {
        {"/JavaScript", "Embedded JavaScript Engine Execution"},
        {"/JS", "Raw JS Script Object"},
        {"/Launch", "External System Command Launch Directive"},
        {"/EmbeddedFiles", "Hidden Embedded File Extraction"},
        {"/OpenAction", "Auto-Execution Action on Document Open"},
        {"/AcroForm", "Dynamic Form Action Execution"}
    };

    result.clean_buffer.assign(raw_bytes, raw_bytes + size);

    for (const auto& [tag, desc] : dangerous_tags) {
        size_t pos = 0;
        while ((pos = content.find(tag, pos)) != std::string::npos) {
            result.malicious_elements_found = true;
            result.stripped_objects_count++;
            result.threat_details.push_back(desc + " at offset " + std::to_string(pos));

            // Neutralize tag in clean buffer by overwriting with harmless comments (0x25 = '%')
            for (size_t i = 0; i < tag.size() && (pos + i) < result.clean_buffer.size(); ++i) {
                result.clean_buffer[pos + i] = '%';
            }
            pos += tag.size();
        }
    }

    return result;
}

} // namespace sentinel::modules::cdr