#include "uefi_image_parser.hpp"
#include <cstring>

namespace sentinel::modules::fse {

FirmwareVolumeHeader UEFIImageParser::parse_volume_header(const uint8_t* raw_bytes, size_t size) {
    FirmwareVolumeHeader header{};
    header.is_valid = false;

    if (!raw_bytes || size < 64) {
        return header;
    }

    std::memcpy(&header.signature, raw_bytes + 40, sizeof(uint32_t));

    // Check for '_FVH' signature
    if (header.signature == 0x4856465F) {
        std::memcpy(header.zero_vector, raw_bytes, 16);
        std::memcpy(header.file_system_guid, raw_bytes + 16, 16);
        std::memcpy(&header.volume_length, raw_bytes + 32, sizeof(uint64_t));
        header.is_valid = true;
    }

    return header;
}

std::vector<std::string> UEFIImageParser::extract_dxe_drivers(const uint8_t* raw_bytes, size_t size) {
    std::vector<std::string> drivers;
    if (!raw_bytes || size < 128) return drivers;

    std::string content(reinterpret_cast<const char*>(raw_bytes), size);
    size_t pos = 0;
    while ((pos = content.find(".dxe", pos)) != std::string::npos) {
        size_t start = (pos >= 16) ? pos - 16 : 0;
        size_t end = std::min(size, pos + 4);
        drivers.push_back(content.substr(start, end - start));
        pos += 4;
    }
    return drivers;
}

} // namespace sentinel::modules::fse