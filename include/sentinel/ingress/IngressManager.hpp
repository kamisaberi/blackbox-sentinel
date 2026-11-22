// File: /home/kami/blackbox-sentinel/include/sentinel/ingress/IngressManager.hpp

#pragma once

#include "sentinel/sdk/abi.hpp"
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace sentinel::ingress {

enum class IngressBusType : uint8_t {
    ETHERNET_NIC = 0, // AF_PACKET / AF_XDP (IPv4/IPv6 + Raw L2 GOOSE/SV/EtherCAT)
    SOCKET_CAN   = 1, // Linux AF_CAN (vcan0/can0) or AF_UNIX CAN-FD datagram bridge
    SHM_RING     = 2, // POSIX /dev/shm lock-free ring buffer (Motion/DMA-BUF simulation)
    TRACEPOINT   = 3  // Reserved for Linux eBPF tracepoints (CWPP)
};

struct alignas(64) ShmRingSlot {
    uint64_t seq;
    uint32_t payload_len;
    uint16_t channel_id;
    uint16_t bus_tag;
    uint8_t payload[4080];
};
static_assert(sizeof(ShmRingSlot) == 4096, "ShmRingSlot must be 4KB page-aligned");

struct ShmRingHeader {
    uint32_t magic;      // 0x53484D52 ("SHMR")
    uint32_t version;    // 1
    uint32_t slot_count; // e.g. 64
    uint32_t slot_size;  // 4096
    std::atomic<uint64_t> write_seq;
    uint8_t reserved[40];
};
static_assert(std::atomic<uint64_t>::is_always_lock_free, "64-bit atomics must be lock-free for IPC");

struct CapturedFrameMeta {
    uint16_t ethertype{0x0800};
    uint8_t transport_proto{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t src_ip_net_order{0};
    std::string src_ip_str{"0.0.0.0"};
    IngressBusType bus{IngressBusType::ETHERNET_NIC};
};

class IngressManager {
public:
    using FrameCallback = std::function<void(const SentinelRawPacket& pkt, const CapturedFrameMeta& meta)>;

    IngressManager() = default;
    ~IngressManager();

    IngressManager(const IngressManager&) = delete;
    IngressManager& operator=(const IngressManager&) = delete;

    /// Bus A: AF_PACKET ETH_P_ALL capture (IPv4 + Raw L2 GOOSE/SV/EtherCAT)
    bool start(const std::string& iface = "");

    /// Bus B: Linux SocketCAN (vcan0/can0) or portable AF_UNIX CAN-FD bridge
    bool start_can(const std::string& can_iface_or_sock = "");

    /// Bus C: POSIX /dev/shm lock-free shared-memory ring buffer
    bool start_shm_ring(const std::string& shm_name = "");

    void stop();

    /// Polls all active buses (AF_PACKET, SocketCAN/UNIX, ShmRing)
    size_t poll_frames(const FrameCallback& cb, int timeout_ms = 25, size_t max_frames = 64);

    [[nodiscard]] bool is_live_capture_active() const noexcept {
        return raw_fd_ >= 0 || can_fd_ >= 0 || can_unix_fd_ >= 0 || shm_hdr_ != nullptr;
    }
    [[nodiscard]] const std::string& active_interface() const noexcept { return iface_; }

private:
    int raw_fd_{-1};
    uint32_t ifindex_{0};
    std::string iface_;

    int can_fd_{-1};
    int can_unix_fd_{-1};
    std::string can_sock_path_;

    int shm_fd_{-1};
    size_t shm_map_size_{0};
    ShmRingHeader* shm_hdr_{nullptr};
    ShmRingSlot* shm_slots_{nullptr};
    uint64_t shm_read_seq_{0};

    static std::string detect_default_interface();
    static bool parse_l2_frame(const uint8_t* buf, size_t len, CapturedFrameMeta& meta);
};

} // namespace sentinel::ingress
