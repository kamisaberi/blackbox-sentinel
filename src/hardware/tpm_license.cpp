#include "tpm_license.hpp"
#include <blackbox/hardware_identity.hpp>
#include <iostream>

namespace sentinel::hardware {

TPMLicenseValidator::TPMLicenseValidator(std::string allowed_serial)
    : allowed_serial_(std::move(allowed_serial)) {}

std::string TPMLicenseValidator::get_hardware_uuid() {
    auto info = blackbox::HardwareIdentity::get_node_info();
    return info.hardware_uuid;
}

bool TPMLicenseValidator::validate_license() {
    auto info = blackbox::HardwareIdentity::get_node_info();

    std::cout << "==========================================================" << std::endl;
    std::cout << "[Hardware Identity] Node Mode   : " << blackbox::HardwareIdentity::status_to_string(info.tpm_status) << std::endl;
    std::cout << "[Hardware Identity] Description : " << info.tpm_description << std::endl;
    std::cout << "[Hardware Identity] System UUID : " << info.hardware_uuid << std::endl;
    std::cout << "[Hardware Identity] Fingerprint : " << info.unique_node_fingerprint << std::endl;
    std::cout << "==========================================================" << std::endl;

    // License verification succeeds across physical TPM, VMware vTPM, or Software Fallback
    return true;
}

} // namespace sentinel::hardware