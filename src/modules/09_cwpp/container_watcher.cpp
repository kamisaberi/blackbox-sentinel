#include "container_watcher.hpp"

namespace sentinel::modules::cwpp {

void ContainerWatcher::track_container(const std::string& cid, const std::string& image, bool privileged) {
    std::lock_guard<std::mutex> lock(watcher_mutex_);
    containers_[cid] = {cid, image, "default-ns", privileged, 0};
}

bool ContainerWatcher::record_anomaly(const std::string& cid, uint32_t& out_total) {
    std::lock_guard<std::mutex> lock(watcher_mutex_);
    auto it = containers_.find(cid);
    if (it != containers_.end()) {
        it->second.anomaly_counter++;
        out_total = it->second.anomaly_counter;
        return true;
    }
    out_total = 1;
    return false;
}

} // namespace sentinel::modules::cwpp