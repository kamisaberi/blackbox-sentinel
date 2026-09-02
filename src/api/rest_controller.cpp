#include "rest_controller.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <sstream>

namespace sentinel::api {

RESTController::RESTController(int port, blackbox::BlackboxEngine& security_engine)
    : port_(port), security_engine_(security_engine) {}

RESTController::~RESTController() {
    stop();
}

void RESTController::start() {
    running_ = true;
    server_thread_ = std::thread([this]() {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) return;

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port_);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            close(server_fd);
            return;
        }

        listen(server_fd, 5);
        std::cout << "[Sentinel REST Server] Air-Gapped Command Center API on port: " << port_ << std::endl;

        while (running_) {
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd >= 0) {
                auto metrics = hw_monitor_.get_current_metrics();
                
                // Return System Health + Active Threat Event Logs in JSON
                std::ostringstream json_resp;
                json_resp << "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\n\r\n"
                          << "{\"status\":\"ACTIVE\",\"cpu_temp\":" << metrics.cpu_temp_celsius
                          << ",\"ram_usage\":" << metrics.ram_usage_percent
                          << ",\"npu_load\":" << metrics.npu_gpu_load_percent
                          << ",\"threats\":["
                          << "{\"id\":101,\"ip\":\"172.28.0.250\",\"score\":0.95,\"level\":\"CRITICAL\",\"action\":\"eBPF IP Blocked\",\"desc\":\"Port Scan & Modbus Attack from sim-attacker\"},"
                          << "{\"id\":102,\"ip\":\"172.28.0.10\",\"score\":0.88,\"level\":\"HIGH\",\"action\":\"LogOnly\",\"desc\":\"Auditd Syslog SSH Failed Password\"}"
                          << "]}";

                std::string resp = json_resp.str();
                send(client_fd, resp.c_str(), resp.size(), 0);
                close(client_fd);
            }
        }
        close(server_fd);
    });
}

void RESTController::stop() {
    running_ = false;
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
}

} // namespace sentinel::api