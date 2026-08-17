#pragma once
#include <string>

namespace sentinel::hardware {

class TPMLicenseValidator {
public:
    explicit TPMLicenseValidator(std::string allowed_serial);
    ~TPMLicenseValidator() = default;

    // Validates hardware node serial & TPM 2.0 key
    bool validate_license();
    std::string get_hardware_uuid();

private:
    std::string allowed_serial_;
};

} // namespace sentinel::hardware