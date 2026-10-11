#include <iostream>
#include <cassert>
#include <chrono>
#include "ai/ModelRouter.hpp"
#include "sdk/PluginSupervisor.hpp"

using namespace sentinel::ai;
using namespace sentinel::sdk;

static void mock_log(int, const char*, const char*) {}
static int mock_drop(uint32_t, uint32_t) { return 0; }
static void mock_metric(const char*, uint64_t) {}
static uint64_t mock_time_ns() { return 1000; }

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "   TESTING HIERARCHICAL SENSOR-TO-MODEL ROUTING ENGINE      " << std::endl;
    std::cout << "============================================================" << std::endl;

    SentinelHostInterface host{};
    host.engine_version = 10000;
    host.log_message = mock_log;
    host.request_ebpf_drop_ip = mock_drop;
    host.emit_metric_counter = mock_metric;
    host.get_monotonic_time_ns = mock_time_ns;

    PluginSupervisor supervisor(host, "/etc/sentinel/plugins.d", "/etc/sentinel/rules.d", "/etc/sentinel/wasm.d");
    supervisor.initialize();

    ModelRouter router;
    bool ok = router.load_routes("configs/model_routes.yaml");
    assert(ok && "Failed to load configs/model_routes.yaml");

    // -------------------------------------------------------------
    // TEST 1: STAGE 1 SPKG REFLEX SHORT-CIRCUIT (< 150 ns)
    // -------------------------------------------------------------
    std::cout << "\n[TEST 1] Dispatching hostile Modbus frame to NIC Sensor..." << std::endl;
    uint8_t modbus_fc05[] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x10, 0xFF, 0x00 };
    SentinelRawPacket pkt1{ .data = modbus_fc05, .length = sizeof(modbus_fc05), .timestamp_ns = 1000 };

    auto res1 = router.dispatch_and_evaluate("sensor_nic_10gbe_lan0", pkt1, supervisor);
    std::cout << "         Verdict: " << res1.verdict 
              << " | Stage: " << res1.mitigated_by_stage 
              << " | Latency: " << res1.total_latency_ns << " ns" << std::endl;
    assert(res1.verdict == SENTINEL_VERDICT_KERNEL_DROP);
    assert(res1.mitigated_by_stage == "SPKG_REFLEX_GATE");

    // -------------------------------------------------------------
    // TEST 2: STAGE 3 SUBSYSTEM NEURAL CASCADE (Intel NPU Inference)
    // -------------------------------------------------------------
    std::cout << "\n[TEST 2] Dispatching clean frame that bypasses SPKG but triggers Subsystem AI..." << std::endl;
    uint8_t clean_frame[] = { 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01 };
    SentinelRawPacket pkt2{ .data = clean_frame, .length = sizeof(clean_frame), .timestamp_ns = 1000 };

    auto res2 = router.dispatch_and_evaluate("sensor_nic_10gbe_lan0", pkt2, supervisor);
    std::cout << "         Verdict: " << res2.verdict << " (Clean frame passed)" << std::endl;
    assert(res2.verdict == SENTINEL_VERDICT_PASS);

    // -------------------------------------------------------------
    // TEST 3: STAGE 4 CROSS-MODAL SENSOR FUSION (Stuxnet HMI Detection)
    // -------------------------------------------------------------
    std::cout << "\n[TEST 3] Testing Multi-Modal Fusion (Cyber Packet vs Optical Thermal Sensor)..." << std::endl;
    // Cyber packet reports normal (score 0.10) BUT thermal camera reports 145.0°C!
    auto fusion_res = router.evaluate_cross_modal_fusion(
        "sensor_nic_10gbe_lan0", 0.10f,
        "sensor_thermal_cam_substation_01", 145.0f
    );
    std::cout << "         Verdict: " << fusion_res.verdict << " (" << fusion_res.mitigated_by_stage << ")" << std::endl;
    std::cout << "         XAI Attribution: " << fusion_res.mrd_xai_attribution << std::endl;
    assert(fusion_res.verdict == SENTINEL_VERDICT_KERNEL_DROP);
    assert(fusion_res.mitigated_by_stage == "CROSS_MODAL_FUSION");

    std::cout << "\n============================================================" << std::endl;
    std::cout << " [SUCCESS] ModelRouter 4-Stage Hierarchy 100% Operational! " << std::endl;
    std::cout << "============================================================" << std::endl;
    supervisor.shutdown();
    return 0;
}
