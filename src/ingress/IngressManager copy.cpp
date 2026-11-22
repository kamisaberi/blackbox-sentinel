// File: /home/kami/blackbox-sentinel/src/ingress/IngressManager.cpp

#include "sentinel/ingress/IngressManager.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sentinel::ingress {

IngressManager::~IngressManager() {
    stop();
}

std::string IngressManager::detect_default_interface() {
    if (const char* env_if = std::getenv("SENTINEL_IFACE")) {
        if (env_if[0] != '\0') return std::string(env_if);
    }

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0 || !ifaddr) {
        return "eth0";
    }

    std::string chosen = "eth0";
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        if ((ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                chosen = ifa->ifa_name;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return chosen;
}

bool IngressManager::start(const std::string& iface) {
    stop();

    if (const char* mode = std::getenv("SENTINEL_INGRESS_MODE")) {
        if (std::string(mode) == "sim_only") {
            std::cout << "[IngressManager] SENTINEL_INGRESS_MODE=sim_only -> live NIC capture disabled.\n";
            return false;
        }
    }

    iface_ = iface.empty() ? detect_default_interface() : iface;
    ifindex_ = if_nametoindex(iface_.c_str());
    if (ifindex_ == 0) {
        std::cerr << "[IngressManager] Interface '" << iface_ << "' not found; running in fallback mode.\n";
        return false;
    }

    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "[IngressManager] AF_PACKET SOCK_RAW unavailable (needs CAP_NET_RAW); running in fallback mode.\n";
        return false;
    }

    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = static_cast<int>(ifindex_);

    if (bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        std::cerr << "[IngressManager] Failed to bind AF_PACKET on " << iface_ << "; running in fallback mode.\n";
        close(fd);
        return false;
    }

    raw_fd_ = fd;
    std::cout << "[+] [IngressManager] Live Raw L2 + IP capture active on '" << iface_
              << "' (ifindex=" << ifindex_ << ", ETH_P_ALL)\n";
    return true;
}

void IngressManager::stop() {
    if (raw_fd_ >= 0) {
        close(raw_fd_);
        raw_fd_ = -1;
    }
}

static bool is_control_plane_port(uint16_t p) noexcept {
    return (p == 22 || p == 50051 || p == 9443 || p == 9444 || p == 8443);
}

bool IngressManager::parse_l2_frame(const uint8_t* buf, size_t len, CapturedFrameMeta& meta) {
    if (!buf || len < 14) return false;

    size_t l3_off = 14;
    uint16_t ethertype = (static_cast<uint16_t>(buf[12]) << 8) | buf[13];

    // Skip single 802.1Q VLAN tag if present
    if (ethertype == 0x8100 && len >= 18) {
        ethertype = (static_cast<uint16_t>(buf[16]) << 8) | buf[17];
        l3_off = 18;
    }

    meta.ethertype = ethertype;
    meta.bus = IngressBusType::ETHERNET_NIC;

    // Non-IP Layer-2 Real-Time Industrial Frames (IEC 61850 GOOSE / SV / EtherCAT)
    if (ethertype == 0x88B8 || ethertype == 0x88BA || ethertype == 0x88A4) {
        meta.transport_proto = 0;
        meta.src_port = 0;
        meta.dst_port = 0;
        meta.src_ip_net_order = 0;
        meta.src_ip_str = "0.0.0.0";
        return true;
    }

    // IPv4
    if (ethertype == 0x0800 && len >= l3_off + 20) {
        const uint8_t* ip = buf + l3_off;
        const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4U;
        if (ihl < 20 || len < l3_off + ihl) return false;

        meta.transport_proto = ip[9];
        std::memcpy(&meta.src_ip_net_order, ip + 12, 4);

        char ip_buf[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, ip + 12, ip_buf, sizeof(ip_buf));
        meta.src_ip_str = ip_buf;

        const size_t l4_off = l3_off + ihl;
        if ((meta.transport_proto == 6 || meta.transport_proto == 17 || meta.transport_proto == 132) &&
            len >= l4_off + 4) {
            meta.src_port = (static_cast<uint16_t>(buf[l4_off]) << 8) | buf[l4_off + 1];
            meta.dst_port = (static_cast<uint16_t>(buf[l4_off + 2]) << 8) | buf[l4_off + 3];

            if (is_control_plane_port(meta.src_port) || is_control_plane_port(meta.dst_port)) {
                return false; // Never inspect Nexus gRPC/HTTP/SSH control plane
            }
        }
        return true;
    }

    return false;
}

size_t IngressManager::poll_frames(const FrameCallback& cb, int timeout_ms, size_t max_frames) {
    if (raw_fd_ < 0 || !cb) return 0;

    pollfd pfd{};
    pfd.fd = raw_fd_;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0 || !(pfd.revents & POLLIN)) {
        return 0;
    }

    uint8_t buf[2048];
    size_t count = 0;

    while (count < max_frames) {
        ssize_t n = recvfrom(raw_fd_, buf, sizeof(buf), 0, nullptr, nullptr);
        if (n <= 0) break;

        CapturedFrameMeta meta;
        if (!parse_l2_frame(buf, static_cast<size_t>(n), meta)) {
            continue;
        }

        const uint64_t now_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());

        SentinelRawPacket pkt{
            .data = buf,
            .length = static_cast<size_t>(n),
            .timestamp_ns = now_ns,
            .ingress_ifindex = ifindex_,
            .network_proto = meta.ethertype,
            .transport_proto = meta.transport_proto,
            .reserved = static_cast<uint8_t>(meta.bus)
        };

        cb(pkt, meta);
        count++;
    }

    return count;
}

} // namespace sentinel::ingress