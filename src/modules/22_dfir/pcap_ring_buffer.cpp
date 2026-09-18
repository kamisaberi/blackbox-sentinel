#include "pcap_ring_buffer.hpp"
#include <fstream>
#include <cstring>

namespace sentinel::modules::dfir {

#pragma pack(push, 1)
struct PCAPGlobalHeader {
    uint32_t magic_number{0xa1b2c3d4};
    uint16_t version_major{2};
    uint16_t version_minor{4};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{65535};
    uint32_t network{1}; // LINKTYPE_ETHERNET
};

struct PCAPRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

PCAPRingBuffer::PCAPRingBuffer(size_t max_packets)
    : max_packets_(max_packets) {
    buffer_.reserve(max_packets_);
}

void PCAPRingBuffer::push_packet(const uint8_t* data, size_t len) {
    if (!data || len == 0) return;

    std::lock_guard<std::mutex> lock(buffer_mutex_);
    RawPacketRecord rec;
    rec.timestamp = std::chrono::system_clock::now();
    rec.packet_data.assign(data, data + len);

    if (buffer_.size() < max_packets_) {
        buffer_.push_back(std::move(rec));
    } else {
        buffer_[head_idx_] = std::move(rec);
        head_idx_ = (head_idx_ + 1) % max_packets_;
    }
}

bool PCAPRingBuffer::dump_to_pcap(const std::string& output_path, std::chrono::seconds window_sec) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    std::ofstream pcap(output_path, std::ios::binary);
    if (!pcap.is_open()) return false;

    PCAPGlobalHeader gh;
    pcap.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    auto now = std::chrono::system_clock::now();

    for (const auto& pkt : buffer_) {
        if ((now - pkt.timestamp) <= window_sec) {
            auto sec = std::chrono::duration_cast<std::chrono::seconds>(pkt.timestamp.time_since_epoch()).count();
            auto usec = std::chrono::duration_cast<std::chrono::microseconds>(pkt.timestamp.time_since_epoch()).count() % 1000000;

            PCAPRecordHeader ph;
            ph.ts_sec = static_cast<uint32_t>(sec);
            ph.ts_usec = static_cast<uint32_t>(usec);
            ph.incl_len = static_cast<uint32_t>(pkt.packet_data.size());
            ph.orig_len = static_cast<uint32_t>(pkt.packet_data.size());

            pcap.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
            pcap.write(reinterpret_cast<const char*>(pkt.packet_data.data()), pkt.packet_data.size());
        }
    }

    return true;
}

} // namespace sentinel::modules::dfir