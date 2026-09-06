#include "cdr_module.hpp"
#include <iostream>

namespace sentinel::modules::cdr {

CdrModule::CdrModule()
    : pdf_sanitizer_(std::make_unique<PDFSanitizer>()),
      docx_sanitizer_(std::make_unique<DOCXSanitizer>()) {}

bool CdrModule::initialize(const std::string& config_json) {
    (void)config_json;
    std::cout << "[Module 16] CDR Content Disarm & Reconstruction Engine initialized." << std::endl;
    return true;
}

bool CdrModule::start() {
    running_ = true;
    std::cout << "[Module 16] CDR Content Disarm & Reconstruction Engine started." << std::endl;
    return true;
}

void CdrModule::stop() {
    running_ = false;
    std::cout << "[Module 16] CDR Content Disarm & Reconstruction Engine stopped." << std::endl;
}

void CdrModule::on_security_event(blackbox::SecurityEvent& event) {
    if (!running_) return;

    // Check PDF payloads
    if (event.description.find("%PDF") != std::string::npos || event.description.find(".pdf") != std::string::npos) {
        auto res = pdf_sanitizer_->sanitize_pdf_stream(
            reinterpret_cast<const uint8_t*>(event.description.data()),
            event.description.size()
        );

        if (res.malicious_elements_found) {
            event.anomaly_score = 0.98f;
            event.level = blackbox::ThreatLevel::Critical;
            event.description += " [CDR Disarmed: Stripped " + std::to_string(res.stripped_objects_count) + " malicious active PDF objects]";
        }
    }

    // Check Office XML / DDE exploits
    std::string finding;
    if (docx_sanitizer_->detect_dde_exploit(event.description, finding)) {
        event.anomaly_score = 0.99f;
        event.level = blackbox::ThreatLevel::Critical;
        event.description += " [CDR Intercepted: " + finding + "]";
    }
}

bool CdrModule::is_healthy() const {
    return running_;
}

} // namespace sentinel::modules::cdr