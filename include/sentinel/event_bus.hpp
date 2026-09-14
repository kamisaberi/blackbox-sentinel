#pragma once

#include "module_interface.hpp"
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>

namespace sentinel {

class EventBus {
public:
    static EventBus& instance() {
        static EventBus bus;
        return bus;
    }

    // Subscribe a module to the event stream
    void subscribe(std::shared_ptr<ISentinelModule> module) {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        if (module) {
            subscribers_.push_back(module);
        }
    }

    // Unsubscribe a module
    void unsubscribe(ModuleID id) {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        subscribers_.erase(
            std::remove_if(subscribers_.begin(), subscribers_.end(),
                [id](const std::shared_ptr<ISentinelModule>& m) {
                    return m && m->get_id() == id;
                }),
            subscribers_.end()
        );
    }

    // Publish an event asynchronously across all active module subscribers
    void publish(blackbox::SecurityEvent& event) {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        for (auto& module : subscribers_) {
            if (module && module->is_healthy()) {
                module->on_security_event(event);
            }
        }
    }

    // Clear all subscriptions
    void clear() {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        subscribers_.clear();
    }

    size_t subscriber_count() {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        return subscribers_.size();
    }

private:
    EventBus() = default;
    ~EventBus() = default;

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    std::vector<std::shared_ptr<ISentinelModule>> subscribers_;
    std::mutex bus_mutex_;
};

} // namespace sentinel