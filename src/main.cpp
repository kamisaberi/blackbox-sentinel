#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>

#include <blackbox/blackbox.hpp>
#include "hardware/tpm_license.hpp"
#include "hardware/hw_monitor.hpp"
#include "exporter/report_generator.hpp"
#include "api/rest_controller.hpp"

std::atomic<bool> g_appliance_running{true};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n[Blackbox Sentinel] Shutting down appliance service..." << std::endl;
        g_appliance_running = false;
    }
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "==========================================================" << std::endl;
    std::cout << "  BLACKBOX SENTINEL™ Cyber-Physical Threat Defense Node   " << std::endl;
    std::cout << "  Powered by libblackbox.so & libxinfer.so                " << std::endl;
    std::cout << "==========================================================" << std::endl;

    // 1. Validate TPM 2.0 Hardware Licensing
    sentinel::hardware::TPMLicenseValidator license_validator("DEVELOPMENT_MODE");
    if (!license_validator.validate_license()) {
        std::cerr << "[CRITICAL] Hardware license validation failed! Exiting." << std::endl;
        return -1;
    }

    try {
        // 2. Initialize Layer 2 Blackbox Shared Library Engine
        blackbox::BlackboxEngine security_engine("configs/blackbox.json");
        security_engine.start();

        // 3. Initialize Layer 3 Commercial REST Server
        sentinel::api::RESTController api_server(8443, security_engine);
        api_server.start();

        // 4. Generate CMMC Compliance Report
        sentinel::exporter::ReportGenerator::generate_cmmc_compliance_report("cmmc_audit_report.txt");

        std::cout << "[Blackbox Sentinel] Appliance Fully Operational. Command Center Active.\n" << std::endl;

        // 5. Appliance Main Loop
        uint64_t counter = 0;
        while (g_appliance_running) {
            counter++;
            
            // Periodically submit security telemetry from appliance
            blackbox::SecurityEvent event;
            event.event_id = counter;
            event.type = blackbox::EventType::NetworkPacket;
            event.source_ip = "192.168.1." + std::to_string(100 + (counter % 30));
            event.features = {0.1f, 0.4f, (counter % 5 == 0 ? 0.95f : 0.1f), 0.2f};

            security_engine.submit_event(event);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Graceful Cleanup
        api_server.stop();
        security_engine.stop();

    } catch (const std::exception& e) {
        std::cerr << "[Sentinel Appliance Error] " << e.what() << std::endl;
        return -1;
    }

    std::cout << "[Blackbox Sentinel] Appliance Service Stopped Gracefully." << std::endl;
    return 0;
}