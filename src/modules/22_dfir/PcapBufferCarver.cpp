#include "PcapBufferCarver.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <openssl/sha.h>

namespace sentinel::dfir {

void PcapBufferCarver::initialize(const std::string& storage_directory, size_t ring_capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    storage_dir_ = storage_directory;
    capacity_ = ring_capacity;
    std::filesystem::create_directories(storage_dir_);
}

void PcapBufferCarver::ingest_packet(uint32_t src_ip, uint32_t dst_ip, const uint8_t* frame, size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    BufferedPacket pkt{
        .timestamp_ns = now_ns,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .raw_frame_bytes = std::vector<uint8_t>(frame, frame + length)
    };

    packet_ring_.push_back(std::move(pkt));
    if (packet_ring_.size() > capacity_) {
        packet_ring_.pop_front();
    }
}

std::string PcapBufferCarver::calculate_file_sha256(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f.is_open()) return "";

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buf[16384];
    while (f.read(buf, sizeof(buf))) {
        SHA256_Update(&ctx, buf, f.gcount());
    }
    if (f.gcount() > 0) SHA256_Update(&ctx, buf, f.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool PcapBufferCarver::carve_incident_evidence(uint32_t attacker_ip, 
                                             const std::string& incident_tag, 
                                             CarvedIncident& out_incident) {
    std::vector<BufferedPacket> packets_to_write;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& p : packet_ring_) {
            if (p.src_ip == attacker_ip || p.dst_ip == attacker_ip) {
                packets_to_write.push_back(p);
            }
        }
        if (packets_to_write.empty()) return false;
    }

    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string filename = "evidence_" + std::to_string(now_sec) + "_" + incident_tag + ".pcap";
    std::filesystem::path pcap_path = std::filesystem::path(storage_dir_) / filename;

    std::ofstream f(pcap_path, std::ios::binary);
    if (!f.is_open()) return false;

    // Write standard PCAP Global Header (24 bytes)
    uint32_t magic = 0xa1b2c3d4;
    uint16_t v_maj = 2, v_min = 4;
    int32_t tz = 0;
    uint32_t sig = 0, snaplen = 65535, network = 1; // Ethernet
    f.write(reinterpret_cast<char*>(&magic), 4);
    f.write(reinterpret_cast<char*>(&v_maj), 2);
    f.write(reinterpret_cast<char*>(&v_min), 2);
    f.write(reinterpret_cast<char*>(&tz), 4);
    f.write(reinterpret_cast<char*>(&sig), 4);
    f.write(reinterpret_cast<char*>(&snaplen), 4);
    f.write(reinterpret_cast<char*>(&network), 4);

    // Write Packets
    for (const auto& p : packets_to_write) {
        uint32_t sec = static_cast<uint32_t>(p.timestamp_ns / 1'000'000'000ULL);
        uint32_t usec = static_cast<uint32_t>((p.timestamp_ns % 1'000'000'000ULL) / 1000);
        uint32_t len = static_cast<uint32_t>(p.raw_frame_bytes.size());

        f.write(reinterpret_cast<char*>(&sec), 4);
        f.write(reinterpret_cast<char*>(&usec), 4);
        f.write(reinterpret_cast<char*>(&len), 4);
        f.write(reinterpret_cast<char*>(&len), 4);
        f.write(reinterpret_cast<const char*>(p.raw_frame_bytes.data()), len);
    }
    f.close();

    out_incident.incident_id = "INC-" + std::to_string(now_sec);
    out_incident.pcap_filepath = pcap_path.string();
    out_incident.packet_count = packets_to_write.size();
    out_incident.sha256_hash = calculate_file_sha256(pcap_path.string());

    return true;
}

} // namespace sentinel::dfir