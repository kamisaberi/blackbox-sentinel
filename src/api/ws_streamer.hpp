#pragma once
#include <blackbox/blackbox.hpp>
#include <thread>
#include <atomic>

namespace sentinel::api {

class WebSocketStreamer {
public:
    explicit WebSocketStreamer(int port);
    ~WebSocketStreamer();

    void start();
    void stop();
    void broadcast_event(const blackbox::SecurityEvent& event);

private:
    int port_;
    std::atomic<bool> running_{false};
    std::thread ws_thread_;
};

} // namespace sentinel::api