#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace sentinel::modules::fse {

class BackdoorScanner {
public:
    BackdoorScanner();
    ~BackdoorScanner() = default;

    bool scan_for_rootkit_signatures(const uint8_t* raw_bytes, size_t size, std::string& out_finding);

private:
    std::vector<std::pair<std::string, std::string>> known_signatures_;
};

} // namespace sentinel::modules::fse