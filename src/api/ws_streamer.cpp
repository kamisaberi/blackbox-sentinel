#include "ws_streamer.hpp"
#include <iostream>
#include <chrono>

namespace sentinel::api {

WebSocketStreamer::WebSocketStreamer(int port) : port_(port) {}

WebSocketStreamer::~WebSocketStreamer() {
    stop();
}

void WebSocketStreamer::start() {
    running_ = true;
    ws_thread_ = std::thread([this]() {
        std::cout << "[WebSocket Streamer] Active on port " << port_ 
                  << " (Pushing live incident stream to Web UI)." << std::endl;
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

void WebSocketStreamer::stop() {
    running_ = false;
    if (ws_thread_.joinable()) {
        ws_thread_.join();
    }
}

void WebSocketStreamer::broadcast_event(const blackbox::SecurityEvent& event) {
    if (!running_) return;
    std::cout << "[WebSocket Streamer] Broadcast Event #" << event.event_id 
              << " | Source IP: " << event.source_ip 
              << " | Score: " << event.anomaly_score << std::endl;
}

} // namespace sentinel::api