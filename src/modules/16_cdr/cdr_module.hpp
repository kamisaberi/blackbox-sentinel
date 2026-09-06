#pragma once

#include "sentinel/module_interface.hpp"
#include "pdf_sanitizer.hpp"
#include "docx_sanitizer.hpp"
#include <atomic>
#include <memory>

namespace sentinel::modules::cdr {

class CdrModule : public ISentinelModule {
public:
    CdrModule();
    ~CdrModule() override = default;

    ModuleID get_id() const override { return ModuleID::CDR; }
    const char* get_name() const override { return "16_cdr"; }

    bool initialize(const std::string& config_json) override;
    bool start() override;
    void stop() override;
    void on_security_event(blackbox::SecurityEvent& event) override;
    bool is_healthy() const override;

private:
    std::atomic<bool> running_{false};
    std::unique_ptr<PDFSanitizer> pdf_sanitizer_;
    std::unique_ptr<DOCXSanitizer> docx_sanitizer_;
};

} // namespace sentinel::modules::cdr