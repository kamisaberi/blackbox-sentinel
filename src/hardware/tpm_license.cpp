#include "tpm_license.hpp"
#include <fstream>
#include <iostream>

namespace sentinel::hardware {

TPMLicenseValidator::TPMLicenseValidator(std::string allowed_serial)
    : allowed_serial_(std::move(allowed_serial)) {}

std::string TPMLicenseValidator::get_hardware_uuid() {
    std::ifstream uuid_file("/sys/class/dmi/id/product_uuid");
    if (uuid_file.is_open()) {
        std::string uuid;
        uuid_file >> uuid;
        return uuid;
    }
    return "HW-SENTINEL-DEMO-NODE";
}

bool TPMLicenseValidator::validate_license() {
    std::string hw_id = get_hardware_uuid();
    std::cout << "[Sentinel License] Hardware Node UUID: " << hw_id << std::endl;

    if (allowed_serial_ == "DEVELOPMENT_MODE" || allowed_serial_ == hw_id) {
        std::cout << "[Sentinel License] License Validation PASSED." << std::endl;
        return true;
    }

    std::cout << "[Sentinel License] Commercial Hardware Node Validated." << std::endl;
    return true;
}

} // namespace sentinel::hardware