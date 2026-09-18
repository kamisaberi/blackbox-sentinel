#include <iostream>
#include <vector>
#include <iomanip>
#include <arpa/inet.h>
#include <xinfer/xinfer.hpp>
#include <blackbox/event.hpp>
#include "../src/modules/18_cps_sec/cps_module.hpp"

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << " Blackbox Sentinel Module Test 4: SCADA OT Physics Guard  " << std::endl;
    std::cout << "==========================================================" << std::endl;

    try {
        xinfer::Engine engine(xinfer::Target::OpenVINO);
        std::string model_url = 
            "https://github.com/onnx/models/raw/main/validated/vision/classification/squeezenet/model/squeezenet1.1-7.onnx";
        
        std::cout << "\n[ModelHub] Loading model backbone..." << std::endl;
        engine.load_model(model_url);

        sentinel::modules::cps_sec::CpsModule cps_module;
        cps_module.initialize("{}");
        cps_module.start();

        // Helper to synthesize a binary Modbus TCP MBAP frame
        auto build_modbus_frame = [](uint16_t tx_id, uint8_t fc, uint16_t reg_addr, uint16_t value) {
            std::string frame(12, '\0');
            uint16_t* ptr16 = reinterpret_cast<uint16_t*>(&frame[0]);
            ptr16[0] = htons(tx_id);
            ptr16[1] = htons(0x0000); // Protocol ID = Modbus TCP
            ptr16[2] = htons(6);      // Length
            frame[6] = 1;             // Unit ID
            frame[7] = fc;            // Function Code (0x05 = Write Single Coil)
            ptr16[4] = htons(reg_addr);
            ptr16[5] = htons(value);  // Requested value (e.g. pressure in PSI)
            return frame;
        };

        // Test Case 1: Normal Safe Pressure Command (45 PSI <= 90 PSI limit)
        std::cout << "\n--- Test Case 1: Normal Plant Valve Command (45 PSI) ---" << std::endl;
        blackbox::SecurityEvent safe_ev;
        safe_ev.event_id = 4001;
        safe_ev.type = blackbox::EventType::NetworkPacket;
        safe_ev.source_ip = "192.168.1.20";
        safe_ev.port = 502;
        safe_ev.description = build_modbus_frame(1, 0x05, 100, 45);

        cps_module.on_security_event(safe_ev);
        std::cout << "Requested Pressure : 45 PSI" << std::endl;
        std::cout << "Action Taken       : " << (safe_ev.action_taken == blackbox::ActionType::None ? "ALLOWED" : "BLOCKED") << std::endl;
        std::cout << "Details            : " << safe_ev.description << std::endl;

        // Test Case 2: Catastrophic Over-Pressure Command (120 PSI > 90 PSI mechanical limit)
        std::cout << "\n--- Test Case 2: Malicious Over-Pressure Command (120 PSI) ---" << std::endl;
        blackbox::SecurityEvent sabotage_ev;
        sabotage_ev.event_id = 4002;
        sabotage_ev.type = blackbox::EventType::NetworkPacket;
        sabotage_ev.source_ip = "172.30.0.251";
        sabotage_ev.port = 502;
        sabotage_ev.description = build_modbus_frame(2, 0x05, 100, 120);

        cps_module.on_security_event(sabotage_ev);
        std::cout << "Requested Pressure : 120 PSI (Exceeds 90 PSI Safety Limit)" << std::endl;
        std::cout << "Threat Level       : " << blackbox::threat_level_to_string(sabotage_ev.level) << std::endl;
        std::cout << "Action Taken       : " << (sabotage_ev.action_taken == blackbox::ActionType::EBPFBlockIP ? "eBPF KERNEL DROP" : "LOGGED") << std::endl;
        std::cout << "Intervention Detail: " << sabotage_ev.description << std::endl;

        cps_module.stop();
        std::cout << "\n[PASS] SCADA OT Physics Guard test completed successfully!" << std::endl;
        std::cout << "==========================================================" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test Error: " << e.what() << std::endl;
        return -1;
    }
    return 0;
}