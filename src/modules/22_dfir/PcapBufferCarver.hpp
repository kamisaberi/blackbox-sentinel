#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <deque>
#include <cstdint>

namespace sentinel::dfir {

struct BufferedPacket {
    uint64_t timestamp_ns;
    uint32_t src_ip;
    uint32_t dst_ip;
    std::vector<uint8_t> raw_frame_bytes;
};

struct CarvedIncident {
    std::string incident_id;
    std::string pcap_filepath;
    std::string sha256_hash;
    size_t packet_count;
};

class PcapBufferCarver {
public:
    static PcapBufferCarver& instance() {
        static PcapBufferCarver inst;
        return inst;
    }

    void initialize(const std::string& storage_directory = "/var/log/sentinel/pcaps", 
                    size_t ring_capacity = 2000);

    // Ingests incoming wire frames into circular rolling RAM buffer
    void ingest_packet(uint32_t src_ip, uint32_t dst_ip, const uint8_t* frame, size_t length);

    // Carves the buffer associated with the attacker IP into a signed .pcap file
    bool carve_incident_evidence(uint32_t attacker_ip, 
                                 const std::string& incident_tag, 
                                 CarvedIncident& out_incident);

private:
    PcapBufferCarver() = default;
    static std::string calculate_file_sha256(const std::string& filepath);

    mutable std::mutex mutex_;
    std::string storage_dir_{"/var/log/sentinel/pcaps"};
    size_t capacity_{2000};
    std::deque<BufferedPacket> packet_ring_;
};

} // namespace sentinel::dfir