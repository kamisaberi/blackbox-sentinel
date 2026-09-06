#include "docx_sanitizer.hpp"
#include <algorithm>

namespace sentinel::modules::cdr {

bool DOCXSanitizer::detect_vba_macros(const uint8_t* raw_bytes, size_t size, std::string& out_finding) {
    if (!raw_bytes || size < 30) return false;

    std::string binary_str(reinterpret_cast<const char*>(raw_bytes), size);

    // Check for compiled VBA project file path in ZIP container
    if (binary_str.find("word/vbaProject.bin") != std::string::npos ||
        binary_str.find("vbaData.xml") != std::string::npos) {
        out_finding = "Embedded malicious VBA macro binary container identified";
        return true;
    }

    // Check for OLE object execution
    if (binary_str.find("oleObject") != std::string::npos) {
        out_finding = "External OLE active object link embedded";
        return true;
    }

    return false;
}

bool DOCXSanitizer::detect_dde_exploit(const std::string& xml_content, std::string& out_finding) {
    if (xml_content.empty()) return false;

    // Dynamic Data Exchange (DDE) command injection signatures
    if (xml_content.find("DDEAUTO") != std::string::npos ||
        xml_content.find("DDE (\"") != std::string::npos ||
        xml_content.find("cmd.exe") != std::string::npos ||
        xml_content.find("powershell") != std::string::npos) {
        out_finding = "Weaponized DDE field code command injection pattern detected";
        return true;
    }

    return false;
}

} // namespace sentinel::modules::cdr