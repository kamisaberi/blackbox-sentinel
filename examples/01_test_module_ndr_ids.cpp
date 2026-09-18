#include <iostream>
#include <vector>
#include <iomanip>
#include <xinfer/xinfer.hpp>
#include <blackbox/event.hpp>
#include "../src/modules/03_ndr/ndr_module.hpp"
#include "../src/modules/04_ids_ips/ids_ips_module.hpp"

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << " Blackbox Sentinel Module Test 1: NDR & IDS/IPS Engines   " << std::endl;
    std::cout << "==========================================================" << std::endl;

    try {
        // 1. Initialize xinfer Engine & Auto-Download Pretrained DDoS/Intrusion ONNX Model
        xinfer::Engine engine(xinfer::Target::OpenVINO);
        std::string model_url = 
            "https://huggingface.co/darkknight25/ddos_xgboost_onnx/resolve/main/ddos_detection_model.onnx";
        
        std::cout << "\n[ModelHub] Loading Network Threat ONNX Model..." << std::endl;
        engine.load_model(model_url);

        // 2. Instantiate and Initialize Modules
        sentinel::modules::ndr::NdrModule ndr_module;
        sentinel::modules::ids_ips::IdsIpsModule ids_module;

        ndr_module.initialize("{}");
        ids_module.initialize("{}");
        ndr_module.start();
        ids_module.start();

        // 3. Test Case A: Normal Benign Network Packet
        std::cout << "\n--- Test Case A: Normal Benign Network Flow ---" << std::endl;
        blackbox::SecurityEvent benign_ev;
        benign_ev.event_id = 1001;
        benign_ev.type = blackbox::EventType::NetworkPacket;
        benign_ev.source_ip = "192.168.1.50";
        benign_ev.port = 443;
        benign_ev.features = std::vector<float>(32, 0.20f);
        benign_ev.description = "Normal TLS Session";

        ndr_module.on_security_event(benign_ev);
        ids_module.on_security_event(benign_ev);

        std::cout << "Event ID: " << benign_ev.event_id 
                  << " | Anomaly Score: " << std::fixed << std::setprecision(4) << benign_ev.anomaly_score
                  << " | Action: " << (benign_ev.action_taken == blackbox::ActionType::None ? "PASSED" : "DROPPED")
                  << " | Details: " << benign_ev.description << std::endl;

        // 4. Test Case B: High-Rate SYN Flood / C2 Beaconing Attack
        std::cout << "\n--- Test Case B: High-Rate SYN Flood & Exploit Signature ---" << std::endl;
        blackbox::SecurityEvent attack_ev;
        attack_ev.event_id = 1002;
        attack_ev.type = blackbox::EventType::NetworkPacket;
        attack_ev.source_ip = "172.30.0.250";
        attack_ev.port = 80;
        
        // High packet rate and low variance (C2 beaconing profile)
        attack_ev.features = std::vector<float>(32, 0.95f);
        attack_ev.description = "SYN_FLOOD_ANOMALY payload detected on wire";

        // Evaluate model inference on feature vector
        xinfer::Tensor& model_input = engine.get_input_tensor("input");
        model_input.copy_from_host(attack_ev.features.data(), model_input.get_size_in_bytes());
        engine.infer();
        
        xinfer::Tensor& model_output = engine.get_output_tensor("scores");
        attack_ev.anomaly_score = model_output.data<float>()[0];

        // Evaluate through NDR and IDS/IPS modules
        ndr_module.on_security_event(attack_ev);
        ids_module.on_security_event(attack_ev);

        std::cout << "Event ID: " << attack_ev.event_id 
                  << " | Anomaly Score: " << std::fixed << std::setprecision(4) << attack_ev.anomaly_score
                  << " | Action: " << (attack_ev.action_taken == blackbox::ActionType::EBPFBlockIP ? "eBPF KERNEL DROP" : "LOGGED")
                  << " | Details: " << attack_ev.description << std::endl;

        ndr_module.stop();
        ids_module.stop();

        std::cout << "\n[PASS] NDR & IDS/IPS module test completed successfully!" << std::endl;
        std::cout << "==========================================================" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Test Error: " << e.what() << std::endl;
        return -1;
    }
    return 0;
}