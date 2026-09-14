#include "memory_scanner.hpp"
#include <fstream>
#include <sstream>

namespace sentinel::modules::edr {

bool MemoryScanner::scan_pid_for_injection(uint32_t pid, std::string& out_details) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;

    std::string line;
    while (std::getline(maps_file, line)) {
        // Look for anonymous executable memory pages without backing file: rwxp or r-xp without pathname
        if (line.find("rwxp") != std::string::npos && line.find("/") == std::string::npos) {
            out_details = "Anonymous RWX memory segment detected in PID " + std::to_string(pid);
            return true;
        }
    }
    return false;
}

} // namespace sentinel::modules::edr