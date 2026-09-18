#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace sentinel::modules::fse {

struct FirmwareVolumeHeader {
    uint8_t zero_vector[16];
    uint8_t file_system_guid[16];
    uint64_t volume_length;
    uint32_t signature; // Expected '_FVH' (0x4856465F)
    bool is_valid;
};

class UEFIImageParser {
public:
    UEFIImageParser() = default;
    ~UEFIImageParser() = default;

    FirmwareVolumeHeader parse_volume_header(const uint8_t* raw_bytes, size_t size);
    std::vector<std::string> extract_dxe_drivers(const uint8_t* raw_bytes, size_t size);
};

} // namespace sentinel::modules::fse