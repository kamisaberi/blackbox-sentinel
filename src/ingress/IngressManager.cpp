// File: /home/kami/blackbox-sentinel/src/ingress/IngressManager.cpp

#include "sentinel/ingress/IngressManager.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <linux/videodev2.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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
    if (getifaddrs(&ifaddr) != 0 || !ifaddr) return "eth0";

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
    if (raw_fd_ >= 0) { close(raw_fd_); raw_fd_ = -1; }

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

    // Enable hardware PTP + kernel software RX timestamping (TSN 802.1Qbv precision)
    int ts_flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
                   SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
    (void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &ts_flags, sizeof(ts_flags));

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
    std::cout << "[+] [IngressManager] Bus A (AF_PACKET + SO_TIMESTAMPING) active on '" << iface_
              << "' (ifindex=" << ifindex_ << ")\n";
    return true;
}

bool IngressManager::start_can(const std::string& can_iface_or_sock) {
    if (can_fd_ >= 0) { close(can_fd_); can_fd_ = -1; }
    if (can_unix_fd_ >= 0) { close(can_unix_fd_); can_unix_fd_ = -1; }

    std::string can_if = can_iface_or_sock;
    if (can_if.empty()) {
        if (const char* env_can = std::getenv("SENTINEL_CAN_IFACE")) can_if = env_can;
    }

    if (!can_if.empty() && can_if.find('/') == std::string::npos) {
        unsigned int cidx = if_nametoindex(can_if.c_str());
        if (cidx != 0) {
            int fd = socket(PF_CAN, SOCK_RAW | SOCK_NONBLOCK, CAN_RAW);
            if (fd >= 0) {
                int enable_fd = 1;
                setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_fd, sizeof(enable_fd));
                sockaddr_can addr{};
                addr.can_family = AF_CAN;
                addr.can_ifindex = static_cast<int>(cidx);
                if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
                    can_fd_ = fd;
                    std::cout << "[+] [IngressManager] Bus B (SocketCAN AF_CAN) active on '" << can_if << "'\n";
                    return true;
                }
                close(fd);
            }
        }
    }

    std::string sock_path = (!can_iface_or_sock.empty() && can_iface_or_sock.find('/') != std::string::npos)
                                ? can_iface_or_sock
                                : (std::getenv("SENTINEL_CAN_UNIX_SOCK") ? std::getenv("SENTINEL_CAN_UNIX_SOCK") : "");
    if (sock_path.empty()) return false;

    unlink(sock_path.c_str());
    int ufd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (ufd < 0) return false;

    sockaddr_un uaddr{};
    uaddr.sun_family = AF_UNIX;
    if (sock_path.size() >= sizeof(uaddr.sun_path)) { close(ufd); return false; }
    std::strncpy(uaddr.sun_path, sock_path.c_str(), sizeof(uaddr.sun_path) - 1);

    if (bind(ufd, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) < 0) { close(ufd); return false; }
    chmod(sock_path.c_str(), 0666);

    can_unix_fd_ = ufd;
    can_sock_path_ = sock_path;
    std::cout << "[+] [IngressManager] Bus B (AF_UNIX CAN-FD Bridge) listening on '" << sock_path << "'\n";
    return true;
}

bool IngressManager::start_shm_ring(const std::string& shm_name) {
    if (shm_hdr_ && shm_map_size_ > 0) {
        munmap(shm_hdr_, shm_map_size_);
        shm_hdr_ = nullptr;
        shm_slots_ = nullptr;
    }
    if (shm_fd_ >= 0) { close(shm_fd_); shm_fd_ = -1; }

    std::string target = shm_name;
    if (target.empty()) {
        if (const char* env_shm = std::getenv("SENTINEL_SHM_RING")) target = env_shm;
    }
    if (target.empty()) return false;
    if (target.front() != '/') target = "/" + target;

    constexpr uint32_t SLOTS = 64;
    const size_t total_sz = sizeof(ShmRingHeader) + SLOTS * sizeof(ShmRingSlot);

    int fd = shm_open(target.c_str(), O_CREAT | O_RDWR, 0666);
    if (fd < 0) return false;
    if (ftruncate(fd, static_cast<off_t>(total_sz)) != 0) { close(fd); return false; }

    void* mem = mmap(nullptr, total_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) { close(fd); return false; }

    auto* hdr = static_cast<ShmRingHeader*>(mem);
    if (hdr->magic != 0x53484D52U) {
        hdr->magic = 0x53484D52U;
        hdr->version = 1;
        hdr->slot_count = SLOTS;
        hdr->slot_size = sizeof(ShmRingSlot);
        hdr->write_seq.store(0, std::memory_order_release);
    }

    shm_fd_ = fd;
    shm_map_size_ = total_sz;
    shm_hdr_ = hdr;
    shm_slots_ = reinterpret_cast<ShmRingSlot*>(static_cast<uint8_t*>(mem) + sizeof(ShmRingHeader));
    shm_read_seq_ = hdr->write_seq.load(std::memory_order_acquire);

    std::cout << "[+] [IngressManager] Bus C (POSIX ShmRing) active on '/dev/shm" << target << "'\n";
    return true;
}

bool IngressManager::start_v4l2(const std::string& video_dev) {
    if (v4l2_fd_ >= 0) {
        v4l2_buf_type bt = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        (void)ioctl(v4l2_fd_, VIDIOC_STREAMOFF, &bt);
        for (auto& b : v4l2_bufs_) {
            if (b.start && b.length > 0) munmap(b.start, b.length);
        }
        v4l2_bufs_.clear();
        close(v4l2_fd_);
        v4l2_fd_ = -1;
    }

    std::string dev = video_dev;
    if (dev.empty()) {
        if (const char* env_v = std::getenv("SENTINEL_V4L2_DEV")) dev = env_v;
    }
    if (dev.empty()) return false;

    int fd = open(dev.c_str(), O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        std::cerr << "[IngressManager] V4L2 device '" << dev << "' unavailable.\n";
        return false;
    }

    v4l2_capability cap{};
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0 || !(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
        close(fd);
        return false;
    }

    v4l2_format fmt{};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 640;
    fmt.fmt.pix.height = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;
    (void)ioctl(fd, VIDIOC_S_FMT, &fmt);

    v4l2_requestbuffers req{};
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0 || req.count == 0) {
        close(fd);
        return false;
    }

    v4l2_bufs_.resize(req.count);
    for (uint32_t i = 0; i < req.count; ++i) {
        v4l2_buffer buf{};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;
        if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) { close(fd); return false; }
        void* ptr = mmap(nullptr, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
        if (ptr == MAP_FAILED) { close(fd); return false; }
        v4l2_bufs_[i] = {ptr, buf.length};
        (void)ioctl(fd, VIDIOC_QBUF, &buf);
    }

    v4l2_buf_type bt = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &bt) < 0) {
        for (auto& b : v4l2_bufs_) munmap(b.start, b.length);
        v4l2_bufs_.clear();
        close(fd);
        return false;
    }

    v4l2_fd_ = fd;
    v4l2_dev_ = dev;
    std::cout << "[+] [IngressManager] Bus D (V4L2 / MIPI-CSI2 mmap) active on '" << dev
              << "' (" << v4l2_bufs_.size() << " buffers)\n";
    return true;
}

void IngressManager::stop() {
    if (raw_fd_ >= 0) { close(raw_fd_); raw_fd_ = -1; }
    if (can_fd_ >= 0) { close(can_fd_); can_fd_ = -1; }
    if (can_unix_fd_ >= 0) {
        close(can_unix_fd_);
        can_unix_fd_ = -1;
        if (!can_sock_path_.empty()) unlink(can_sock_path_.c_str());
    }
    if (shm_hdr_ && shm_map_size_ > 0) {
        munmap(shm_hdr_, shm_map_size_);
        shm_hdr_ = nullptr;
        shm_slots_ = nullptr;
    }
    if (shm_fd_ >= 0) { close(shm_fd_); shm_fd_ = -1; }
    if (v4l2_fd_ >= 0) {
        v4l2_buf_type bt = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        (void)ioctl(v4l2_fd_, VIDIOC_STREAMOFF, &bt);
        for (auto& b : v4l2_bufs_) {
            if (b.start && b.length > 0) munmap(b.start, b.length);
        }
        v4l2_bufs_.clear();
        close(v4l2_fd_);
        v4l2_fd_ = -1;
    }
}

static bool is_control_plane_port(uint16_t p) noexcept {
    return (p == 22 || p == 50051 || p == 9443 || p == 9444 || p == 8443);
}

bool IngressManager::parse_l2_frame(const uint8_t* buf, size_t len, CapturedFrameMeta& meta) {
    if (!buf || len < 14) return false;

    size_t l3_off = 14;
    uint16_t ethertype = (static_cast<uint16_t>(buf[12]) << 8) | buf[13];

    if (ethertype == 0x8100 && len >= 18) {
        ethertype = (static_cast<uint16_t>(buf[16]) << 8) | buf[17];
        l3_off = 18;
    }

    meta.ethertype = ethertype;
    meta.bus = IngressBusType::ETHERNET_NIC;

    if (ethertype == 0x88B8 || ethertype == 0x88BA || ethertype == 0x88A4) {
        meta.transport_proto = 0;
        meta.src_port = 0;
        meta.dst_port = 0;
        meta.src_ip_net_order = 0;
        meta.src_ip_str = "0.0.0.0";
        return true;
    }

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
            if (is_control_plane_port(meta.src_port) || is_control_plane_port(meta.dst_port)) return false;
        }
        return true;
    }

    return false;
}

size_t IngressManager::poll_frames(const FrameCallback& cb, int timeout_ms, size_t max_frames) {
    if (!cb || !is_live_capture_active()) return 0;

    auto now_ns_fn = []() -> uint64_t {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
    };

    size_t count = 0;

    // 1. Bus C: Lock-free POSIX ShmRing
    if (shm_hdr_ && shm_slots_ && shm_hdr_->slot_count > 0) {
        const uint64_t wseq = shm_hdr_->write_seq.load(std::memory_order_acquire);
        if (wseq > shm_read_seq_ + shm_hdr_->slot_count) {
            shm_read_seq_ = wseq - shm_hdr_->slot_count;
        }
        while (shm_read_seq_ < wseq && count < max_frames) {
            const ShmRingSlot& slot = shm_slots_[shm_read_seq_ % shm_hdr_->slot_count];
            shm_read_seq_++;
            const size_t plen = std::min<size_t>(slot.payload_len, sizeof(slot.payload));
            if (plen == 0) continue;

            CapturedFrameMeta meta;
            meta.ethertype = 0x0053;
            meta.dst_port = slot.channel_id;
            meta.bus = IngressBusType::SHM_RING;
            meta.src_ip_str = "shm://ring0";

            SentinelRawPacket pkt{
                .data = slot.payload,
                .length = plen,
                .timestamp_ns = now_ns_fn(),
                .ingress_ifindex = 0,
                .network_proto = 0x0053,
                .transport_proto = 0,
                .reserved = static_cast<uint8_t>(IngressBusType::SHM_RING)
            };
            cb(pkt, meta);
            count++;
        }
    }

    // 2. Poll FDs (Bus A: AF_PACKET, Bus B: CAN/UNIX, Bus D: V4L2)
    pollfd pfds[4]{};
    int nfds = 0;
    const int idx_raw  = (raw_fd_ >= 0)      ? (pfds[nfds] = {raw_fd_, POLLIN, 0}, nfds++)      : -1;
    const int idx_can  = (can_fd_ >= 0)      ? (pfds[nfds] = {can_fd_, POLLIN, 0}, nfds++)      : -1;
    const int idx_ucan = (can_unix_fd_ >= 0) ? (pfds[nfds] = {can_unix_fd_, POLLIN, 0}, nfds++) : -1;
    const int idx_v4l2 = (v4l2_fd_ >= 0)     ? (pfds[nfds] = {v4l2_fd_, POLLIN, 0}, nfds++)     : -1;

    if (nfds == 0) return count;
    const int effective_timeout = (count > 0) ? 0 : timeout_ms;
    if (poll(pfds, static_cast<nfds_t>(nfds), effective_timeout) <= 0) return count;

    // 2a. Bus A: AF_PACKET with SO_TIMESTAMPING via recvmsg()
    if (idx_raw >= 0 && (pfds[idx_raw].revents & POLLIN)) {
        uint8_t buf[2048];
        char ctrl[256];
        while (count < max_frames) {
            sockaddr_ll from{};
            iovec iov{buf, sizeof(buf)};
            msghdr msg{};
            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl;
            msg.msg_controllen = sizeof(ctrl);

            ssize_t n = recvmsg(raw_fd_, &msg, 0);
            if (n <= 0) break;
            if (from.sll_pkttype == PACKET_OUTGOING) continue;

            CapturedFrameMeta meta;
            if (!parse_l2_frame(buf, static_cast<size_t>(n), meta)) continue;

            uint64_t ts_ns = now_ns_fn();
            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING &&
                    cmsg->cmsg_len >= CMSG_LEN(3 * sizeof(timespec))) {
                    timespec ts[3]{};
                    std::memcpy(ts, CMSG_DATA(cmsg), sizeof(ts));
                    if (ts[2].tv_sec != 0 || ts[2].tv_nsec != 0) {
                        ts_ns = static_cast<uint64_t>(ts[2].tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts[2].tv_nsec);
                        meta.hw_timestamp_valid = true;
                    } else if (ts[0].tv_sec != 0 || ts[0].tv_nsec != 0) {
                        ts_ns = static_cast<uint64_t>(ts[0].tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts[0].tv_nsec);
                    }
                }
            }

            SentinelRawPacket pkt{
                .data = buf,
                .length = static_cast<size_t>(n),
                .timestamp_ns = ts_ns,
                .ingress_ifindex = ifindex_,
                .network_proto = meta.ethertype,
                .transport_proto = meta.transport_proto,
                .reserved = static_cast<uint8_t>(IngressBusType::ETHERNET_NIC)
            };
            cb(pkt, meta);
            count++;
        }
    }

    // 2b. Bus B: SocketCAN / AF_UNIX CAN-FD
    auto drain_can_fd = [&](int cfd) {
        uint8_t cbuf[sizeof(canfd_frame)];
        while (count < max_frames) {
            ssize_t n = recvfrom(cfd, cbuf, sizeof(cbuf), 0, nullptr, nullptr);
            if (n < static_cast<ssize_t>(sizeof(can_frame))) break;

            uint32_t can_id = 0;
            std::memcpy(&can_id, cbuf, 4);
            can_id &= CAN_EFF_MASK;

            CapturedFrameMeta meta;
            meta.ethertype = 0x000C;
            meta.transport_proto = 0xCA;
            meta.dst_port = static_cast<uint16_t>(can_id & 0x7FFU);
            meta.bus = IngressBusType::SOCKET_CAN;
            meta.src_ip_str = "can://bus0";

            SentinelRawPacket pkt{
                .data = cbuf,
                .length = static_cast<size_t>(n),
                .timestamp_ns = now_ns_fn(),
                .ingress_ifindex = 0,
                .network_proto = 0x000C,
                .transport_proto = 0xCA,
                .reserved = static_cast<uint8_t>(IngressBusType::SOCKET_CAN)
            };
            cb(pkt, meta);
            count++;
        }
    };
    if (idx_can >= 0 && (pfds[idx_can].revents & POLLIN)) drain_can_fd(can_fd_);
    if (idx_ucan >= 0 && (pfds[idx_ucan].revents & POLLIN)) drain_can_fd(can_unix_fd_);

    // 2c. Bus D: V4L2 / MIPI-CSI2 Camera mmap frame dequeue
    if (idx_v4l2 >= 0 && (pfds[idx_v4l2].revents & POLLIN)) {
        v4l2_buffer vbuf{};
        vbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        vbuf.memory = V4L2_MEMORY_MMAP;
        if (ioctl(v4l2_fd_, VIDIOC_DQBUF, &vbuf) == 0 && vbuf.index < v4l2_bufs_.size()) {
            CapturedFrameMeta meta;
            meta.ethertype = 0x0056;
            meta.dst_port = 0;
            meta.bus = IngressBusType::V4L2_CAMERA;
            meta.src_ip_str = "v4l2://" + v4l2_dev_;

            const uint64_t v_ts_ns = static_cast<uint64_t>(vbuf.timestamp.tv_sec) * 1'000'000'000ULL +
                                     static_cast<uint64_t>(vbuf.timestamp.tv_usec) * 1'000ULL;

            SentinelRawPacket pkt{
                .data = static_cast<const uint8_t*>(v4l2_bufs_[vbuf.index].start),
                .length = vbuf.bytesused,
                .timestamp_ns = v_ts_ns > 0 ? v_ts_ns : now_ns_fn(),
                .ingress_ifindex = 0,
                .network_proto = 0x0056,
                .transport_proto = 0,
                .reserved = static_cast<uint8_t>(IngressBusType::V4L2_CAMERA)
            };
            cb(pkt, meta);
            count++;
            (void)ioctl(v4l2_fd_, VIDIOC_QBUF, &vbuf);
        }
    }

    return count;
}

} // namespace sentinel::ingress