#include "backdoor_scanner.hpp"

namespace sentinel::modules::fse {

BackdoorScanner::BackdoorScanner() {
    known_signatures_.push_back({"MoonBounce", "MoonBounce UEFI Bootkit Stage-1 Hook"});
    known_signatures_.push_back({"CosmicStrand", "CosmicStrand MBR/CSM Firmware Rootkit"});
    known_signatures_.push_back({"BlackLotus", "BlackLotus UEFI Secure Boot Bypass"});
    known_signatures_.push_back({"SmmBackdoor", "System Management Mode (SMM) Cache Poisoning"});
}

bool BackdoorScanner::scan_for_rootkit_signatures(const uint8_t* raw_bytes, size_t size, std::string& out_finding) {
    if (!raw_bytes || size < 32) return false;

    std::string data(reinterpret_cast<const char*>(raw_bytes), size);

    for (const auto& [pattern, description] : known_signatures_) {
        if (data.find(pattern) != std::string::npos) {
            out_finding = description;
            return true;
        }
    }

    return false;
}

} // namespace sentinel::modules::fse