#include "process_tracker.hpp"

namespace sentinel::modules::edr {

void ProcessTracker::register_process(uint32_t pid, uint32_t ppid, const std::string& name, const std::string& cmdline) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    process_tree_[pid] = {pid, ppid, name, cmdline};
}

bool ProcessTracker::is_suspicious_lineage(uint32_t pid, std::string& out_reason) {
    std::lock_guard<std::mutex> lock(tree_mutex_);
    auto it = process_tree_.find(pid);
    if (it == process_tree_.end()) return false;

    const auto& child = it->second;
    auto parent_it = process_tree_.find(child.parent_pid);

    if (parent_it != process_tree_.end()) {
        const auto& parent = parent_it->second;

        // Anomaly: Web servers or document readers spawning shells
        if ((parent.process_name == "nginx" || parent.process_name == "apache2" || parent.process_name == "httpd") &&
            (child.process_name == "sh" || child.process_name == "bash" || child.process_name == "dash")) {
            out_reason = "Web server spawned interactive shell: " + parent.process_name + " -> " + child.process_name;
            return true;
        }

        if (parent.process_name == "WINWORD.EXE" && (child.process_name == "cmd.exe" || child.process_name == "powershell.exe")) {
            out_reason = "Document reader spawned command interpreter";
            return true;
        }
    }

    return false;
}

} // namespace sentinel::modules::edr