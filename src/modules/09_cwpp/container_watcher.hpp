#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

namespace sentinel::modules::cwpp {

struct ContainerContext {
    std::string container_id;
    std::string image_name;
    std::string namespace_id;
    bool is_privileged{false};
    uint32_t anomaly_counter{0};
};

class ContainerWatcher {
public:
    ContainerWatcher() = default;
    ~ContainerWatcher() = default;

    void track_container(const std::string& cid, const std::string& image, bool privileged);
    bool record_anomaly(const std::string& cid, uint32_t& out_total);

private:
    std::unordered_map<std::string, ContainerContext> containers_;
    std::mutex watcher_mutex_;
};

} // namespace sentinel::modules::cwpp