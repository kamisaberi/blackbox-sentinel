#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>

namespace sentinel::modules::ddp {

class DecoySSHTrap {
public:
    DecoySSHTrap() = default;
    ~DecoySSHTrap() = default;

    bool record_connection(const std::string& src_ip, uint16_t port);
    size_t trapped_attacker_count();

private:
    std::unordered_map<std::string, uint32_t> trapped_ips_;
    std::mutex ssh_trap_mutex_;
};

} // namespace sentinel::modules::ddp