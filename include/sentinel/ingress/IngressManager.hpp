// File: /home/kami/blackbox-sentinel/include/sentinel/ingress/IngressManager.hpp

#pragma once

#include "sentinel/sdk/abi.hpp"
#include <cstdint>
#include <functional>
#include <string>

namespace sentinel::ingress {

enum class IngressBusType : uint8_t {
    ETHERNET_NIC = 0, // AF_PACKET / AF_XDP (IPv4/IPv6 + Raw L2 GOOSE/SV/EtherCAT)
    SOCKET_CAN   = 1, // Reserved for SocketCAN / CAN-FD (motion-guard)
    SHM_RING     = 2, // Reserved for /dev/shm / DMA-BUF (vision-guard)
    TRACEPOINT   = 3  // Reserved for Linux eBPF tracepoints (CWPP)
};

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

    /// Initializes AF_PACKET ETH_P_ALL capture on iface (auto-detects eth0/NIC if empty).
    /// Falls back cleanly to simulation-only mode if CAP_NET_RAW is unavailable.
    bool start(const std::string& iface = "");
    void stop();

    /// Polls up to max_frames from the live interface with timeout_ms wait.
    /// Returns number of frames dispatched to cb.
    size_t poll_frames(const FrameCallback& cb, int timeout_ms = 25, size_t max_frames = 64);

    [[nodiscard]] bool is_live_capture_active() const noexcept { return raw_fd_ >= 0; }
    [[nodiscard]] const std::string& active_interface() const noexcept { return iface_; }

private:
    int raw_fd_{-1};
    uint32_t ifindex_{0};
    std::string iface_;

    static std::string detect_default_interface();
    static bool parse_l2_frame(const uint8_t* buf, size_t len, CapturedFrameMeta& meta);
};

} // namespace sentinel::ingress