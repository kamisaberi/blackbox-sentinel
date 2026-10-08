#pragma once

#include "abi.hpp"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <optional>
#include <arpa/inet.h>

namespace sentinel::sdk {

class PacketView {
public:
    constexpr PacketView() noexcept : data_(nullptr), length_(0), offset_(0) {}
    
    constexpr PacketView(const uint8_t* data, size_t length, size_t offset = 0) noexcept
        : data_(data), length_(length), offset_(offset) {}

    explicit PacketView(const SentinelRawPacket& raw) noexcept
        : data_(raw.data), length_(raw.length), offset_(0) {}

    [[nodiscard]] constexpr size_t size() const noexcept {
        return (offset_ <= length_) ? (length_ - offset_) : 0;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size() == 0;
    }

    [[nodiscard]] constexpr const uint8_t* data() const noexcept {
        return data_ + offset_;
    }

    [[nodiscard]] constexpr const uint8_t* raw_base() const noexcept {
        return data_;
    }

    [[nodiscard]] constexpr size_t current_offset() const noexcept {
        return offset_;
    }

    [[nodiscard]] constexpr std::optional<uint8_t> peek_u8(size_t at = 0) const noexcept {
        if (offset_ + at >= length_) return std::nullopt;
        return data_[offset_ + at];
    }

    [[nodiscard]] std::optional<uint16_t> read_be16(size_t at = 0) const noexcept {
        if (offset_ + at + 2 > length_) return std::nullopt;
        uint16_t val;
        std::memcpy(&val, data_ + offset_ + at, 2);
        return ntohs(val);
    }

    [[nodiscard]] std::optional<uint32_t> read_be32(size_t at = 0) const noexcept {
        if (offset_ + at + 4 > length_) return std::nullopt;
        uint32_t val;
        std::memcpy(&val, data_ + offset_ + at, 4);
        return ntohl(val);
    }

    [[nodiscard]] std::optional<uint64_t> read_be64(size_t at = 0) const noexcept {
        if (offset_ + at + 8 > length_) return std::nullopt;
        uint64_t val;
        std::memcpy(&val, data_ + offset_ + at, 8);
        return be64toh(val);
    }

    [[nodiscard]] std::optional<PacketView> slice(size_t start, size_t count) const noexcept {
        if (offset_ + start + count > length_) return std::nullopt;
        return PacketView(data_, offset_ + start + count, offset_ + start);
    }

    [[nodiscard]] bool skip(size_t bytes) noexcept {
        if (offset_ + bytes > length_) return false;
        offset_ += bytes;
        return true;
    }

    [[nodiscard]] std::string_view as_string_view() const noexcept {
        return std::string_view(reinterpret_cast<const char*>(data()), size());
    }

    [[nodiscard]] bool starts_with(const void* prefix, size_t prefix_len) const noexcept {
        if (size() < prefix_len) return false;
        return std::memcmp(data(), prefix, prefix_len) == 0;
    }

private:
    const uint8_t* data_;
    size_t         length_;
    size_t         offset_;
};

} // namespace sentinel::sdk