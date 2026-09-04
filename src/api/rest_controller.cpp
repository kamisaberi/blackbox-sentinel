#include "rest_controller.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <filesystem>
#include <cstdlib>

namespace sentinel::api {

static std::string get_mime_type(const std::string& path) {
    if (path.ends_with(".html")) return "text/html";
    if (path.ends_with(".css"))  return "text/css";
    if (path.ends_with(".js"))   return "application/javascript";
    if (path.ends_with(".svg"))  return "image/svg+xml";
    if (path.ends_with(".json")) return "application/json";
    if (path.ends_with(".txt"))  return "text/plain";
    return "application/octet-stream";
}

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

        listen(server_fd, 10);
        std::cout << "[Sentinel Server] Web Command Center & REST API active at http://localhost:" << port_ << std::endl;

        while (running_) {
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd < 0) continue;

            char buffer[4096] = {0};
            ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                close(client_fd);
                continue;
            }

            std::string request(buffer);
            std::istringstream req_stream(request);
            std::string method, path, protocol;
            req_stream >> method >> path >> protocol;

            std::string response;

            // 1. REST API Routing
            if (path == "/api/v1/system-health") {
                auto metrics = hw_monitor_.get_current_metrics();
                std::ostringstream json;
                json << "{\"status\":\"" << (security_engine_.is_running() ? "OPERATIONAL" : "PAUSED") << "\""
                     << ",\"cpu_temp\":" << metrics.cpu_temp_celsius
                     << ",\"ram_usage\":" << metrics.ram_usage_percent
                     << ",\"npu_load\":" << metrics.npu_gpu_load_percent
                     << ",\"threats\":["
                     << "{\"id\":101,\"ip\":\"172.30.0.250\",\"score\":0.98,\"level\":\"CRITICAL\",\"action\":\"eBPF Kernel Drop\",\"desc\":\"Port Scan Flood Blocked\"},"
                     << "{\"id\":102,\"ip\":\"172.30.0.251\",\"score\":0.99,\"level\":\"CRITICAL\",\"action\":\"eBPF Kernel Drop\",\"desc\":\"Unauthorized SCADA Modbus Write\"},"
                     << "{\"id\":103,\"ip\":\"172.30.0.252\",\"score\":0.88,\"level\":\"HIGH\",\"action\":\"Logged\",\"desc\":\"SSH Brute Force Burst\"}"
                     << "]}";

                std::string body = json.str();
                response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: " 
                         + std::to_string(body.size()) + "\r\n\r\n" + body;

            } else if (path == "/api/v1/control/start" && method == "POST") {
                security_engine_.start();
                std::string body = "{\"status\":\"started\"}";
                response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: " 
                         + std::to_string(body.size()) + "\r\n\r\n" + body;

            } else if (path == "/api/v1/control/stop" && method == "POST") {
                security_engine_.stop();
                std::string body = "{\"status\":\"stopped\"}";
                response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: " 
                         + std::to_string(body.size()) + "\r\n\r\n" + body;

            } else if (path == "/api/v1/unblock-ip" && method == "POST") {
                size_t ip_pos = request.find("\"ip_address\":\"");
                if (ip_pos != std::string::npos) {
                    size_t start = ip_pos + 14;
                    size_t end = request.find("\"", start);
                    std::string ip = request.substr(start, end - start);
                    security_engine_.unblock_ip_address(ip);
                    std::cout << "[REST API] Unblocked IP: " << ip << std::endl;
                }
                std::string body = "{\"status\":\"unblocked\"}";
                response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: " 
                         + std::to_string(body.size()) + "\r\n\r\n" + body;

            } else if (path == "/api/v1/simulate-attack" && method == "POST") {
                if (request.find("\"attack_type\":\"nmap\"") != std::string::npos) {
                    std::system("sudo docker exec -d sim-attacker-ddos nmap -sS -p 22,80,443,502,8443 172.30.0.1 >/dev/null 2>&1 &");
                } else if (request.find("\"attack_type\":\"modbus\"") != std::string::npos) {
                    std::system("sudo docker exec -d sim-attacker-scada sh -c \"echo 'MALICIOUS_MODBUS' | nc -w 1 172.30.0.1 502\" >/dev/null 2>&1 &");
                } else if (request.find("\"attack_type\":\"ssh\"") != std::string::npos) {
                    std::system("sudo docker exec -d sim-attacker-bruteforce sh -c \"echo 'SSH_BRUTE' | nc -w 1 172.30.0.1 22\" >/dev/null 2>&1 &");
                }
                std::string body = "{\"status\":\"attack_triggered\"}";
                response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: " 
                         + std::to_string(body.size()) + "\r\n\r\n" + body;

            // 2. Static Web UI File Serving
            } else {
                std::string file_path = "web" + (path == "/" ? "/index.html" : path);
                if (!std::filesystem::exists(file_path)) {
                    file_path = "../web" + (path == "/" ? "/index.html" : path);
                }

                if (std::filesystem::exists(file_path) && !std::filesystem::is_directory(file_path)) {
                    std::ifstream file(file_path, std::ios::binary);
                    std::ostringstream file_contents;
                    file_contents << file.rdbuf();
                    std::string body = file_contents.str();

                    response = "HTTP/1.1 200 OK\r\nContent-Type: " + get_mime_type(file_path) 
                             + "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
                } else {
                    std::string not_found = "<html><body><h1>404 Not Found</h1></body></html>";
                    response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: " 
                             + std::to_string(not_found.size()) + "\r\n\r\n" + not_found;
                }
            }

            send(client_fd, response.c_str(), response.size(), 0);
            close(client_fd);
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