#pragma once
#include "blackbox/blackbox.hpp"
#include "hardware/hw_monitor.hpp"
#include "auth_manager.hpp"
#include <thread>
#include <atomic>

namespace sentinel::api {

class RESTController {
public:
    RESTController(int port, blackbox::BlackboxEngine& security_engine);
    ~RESTController();

    void start();
    void stop();

private:
    int port_;
    blackbox::BlackboxEngine& security_engine_;
    hardware::HardwareMonitor hw_monitor_;
    AuthManager auth_manager_;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
};

} // namespace sentinel::api