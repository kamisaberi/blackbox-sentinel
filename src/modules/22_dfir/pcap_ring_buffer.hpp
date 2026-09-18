#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <cstdint>
#include <chrono>

namespace sentinel::modules::dfir {

struct RawPacketRecord {
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> packet_data;
};

class PCAPRingBuffer {
public:
    explicit PCAPRingBuffer(size_t max_packets = 50000);
    ~PCAPRingBuffer() = default;

    void push_packet(const uint8_t* data, size_t len);
    bool dump_to_pcap(const std::string& output_pcap_path, std::chrono::seconds window_sec);

private:
    size_t max_packets_;
    std::vector<RawPacketRecord> buffer_;
    size_t head_idx_{0};
    std::mutex buffer_mutex_;
};

} // namespace sentinel::modules::dfir