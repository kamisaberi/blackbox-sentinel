#pragma once

#include <string>
#include <unordered_map>
#include <cstdint>
#include <mutex>

namespace sentinel::modules::edr {

struct ProcessNode {
    uint32_t pid;
    uint32_t parent_pid;
    std::string process_name;
    std::string cmdline;
};

class ProcessTracker {
public:
    ProcessTracker() = default;
    ~ProcessTracker() = default;

    void register_process(uint32_t pid, uint32_t ppid, const std::string& name, const std::string& cmdline);
    bool is_suspicious_lineage(uint32_t pid, std::string& out_reason);

private:
    std::unordered_map<uint32_t, ProcessNode> process_tree_;
    std::mutex tree_mutex_;
};

} // namespace sentinel::modules::edr