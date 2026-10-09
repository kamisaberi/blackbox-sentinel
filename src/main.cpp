#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <string>

#include <blackbox/blackbox.hpp>
#include "core/orchestrator.hpp"
#include "hardware/tpm_license.hpp"
#include "hardware/hw_monitor.hpp"
#include "exporter/report_generator.hpp"
#include "api/rest_controller.hpp"
#include "nexus/NexusUplink.hpp"
#include "core/LicenseManager.hpp"
#include "core/ZtpTokenAgent.hpp"
#include "sbom/SbomScanner.hpp"

// Extensibility & eBPF Subsystem Headers
#include "sdk/PluginSupervisor.hpp"
#include "nexus/KernelDropInjector.hpp"

std::atomic<bool> g_appliance_running{true};

void signal_handler(int sig)
{
    (void)sig;
    sentinel::nexus_client::NexusUplink::instance().stop();
    g_appliance_running = false;
}

void print_help(const char* prog_name)
{
    std::cout << "\033[36m\033[1m"
              << "==========================================================\n"
              << "  BLACKBOX SENTINEL™ Cyber-Physical Threat Defense Node   \n"
              << "  Powered by libblackbox.so & libxinfer.so                \n"
              << "==========================================================\033[0m\n\n"
              << "\033[1mUSAGE:\033[0m\n"
              << "  " << prog_name << " [OPTIONS]\n"
              << "  " << prog_name << " [CONFIG_FILE]\n\n"
              << "\033[1mCORE APPLIANCE OPTIONS:\033[0m\n"
              << "  \033[32m-h, --help\033[0m\n"
              << "      Show this help menu and exit.\n\n"

              << "\033[1mEXTENSIBILITY & PLUGIN SUBSYSTEM:\033[0m\n"
              << "  \033[32m--plugins-status, --list-plugins\033[0m\n"
              << "      Inspect real-time telemetry, latencies (P50/Max), and\n"
              << "      quarantine status across all Native C++20, LuaJIT, and Wasm plugins.\n\n"

              << "\033[1mHARDWARE & PROVISIONING TOKENS:\033[0m\n"
              << "  \033[32m--generate-hardware-token\033[0m\n"
              << "      Probe local silicon (TPM 2.0 / DMI UUID) and print the immutable\n"
              << "      hardware licensing token (\033[33mARY-HW-...\033[0m) used to lock .lic envelopes.\n\n"
              << "  \033[32m--generate-ztp-token\033[0m\n"
              << "      Generate a portable Base64 Zero-Touch Provisioning (\033[33mZTP-...\033[0m)\n"
              << "      onboarding envelope containing full hardware and vendor measurements.\n\n"

              << "\033[1mCLOUD LICENSING & SUBSCRIPTION API:\033[0m\n"
              << "  \033[32m--subscribe <plan_slug> [api_url]\033[0m\n"
              << "      Self-service subscribe appliance to a cloud tier (e.g., community, commercial).\n"
              << "      Default API URL: \033[34mhttp://127.0.0.1:8000/api/v1\033[0m\n\n"
              << "  \033[32m--activate [api_url] [jwt_token]\033[0m\n"
              << "      Perform zero-touch online activation or refresh 30-day lease using JWT bearer auth.\n"
              << "      Default API URL: \033[34mhttp://127.0.0.1:8000/api/v1\033[0m\n\n"
              << "  \033[32m--fetch-key [api_url]\033[0m\n"
              << "      Query cloud backend to fetch/update the master Ed25519 public verification key.\n"
              << "      Default API URL: \033[34mhttp://127.0.0.1:8000/api/v1\033[0m\n\n"

              << "\033[1mDEFAULT RUNTIME BEHAVIOR:\033[0m\n"
              << "  If no options are passed, Sentinel initializes the active defense node:\n"
              << "    1. Cryptographically loads & verifies \033[33m/etc/sentinel/license.lic\033[0m.\n"
              << "    2. Exports local CycloneDX SBOM manifest to \033[33m/etc/sentinel/sbom.json\033[0m.\n"
              << "    3. Starts Layer 2 eBPF kernel dropper & 26 decoupled native subsystems.\n"
              << "    4. Launches 3-Tier Extensibility Subsystem (Native C++20, LuaJIT, Wasm3).\n"
              << "    5. Launches local Web Command Center on port \033[34m8443\033[0m.\n"
              << "    6. Connects NexusUplink gRPC client to Sentinel Nexus (\033[34m50051\033[0m).\n\n"

              << "\033[1mEXAMPLES:\033[0m\n"
              << "  sudo " << prog_name << " --help\n"
              << "  sudo " << prog_name << " --plugins-status\n"
              << "  sudo " << prog_name << " --generate-hardware-token\n"
              << "  sudo " << prog_name << " --subscribe community http://127.0.0.1:8000/api/v1\n"
              << "  sudo " << prog_name << " --activate http://127.0.0.1:8000/api/v1 \"eyJh...\"\n"
              << "  sudo " << prog_name << " /etc/sentinel/sentinel.yaml\n"
              << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        std::string cmd = argv[1];

        if (cmd == "-h" || cmd == "--help")
        {
            print_help(argv[0]);
            return 0;
        }

        // --- NEW EXTENSION TELEMETRY CLI OPTION ---
        if (cmd == "--plugins-status" || cmd == "--list-plugins")
        {
            SentinelHostInterface host{};
            host.engine_version = 10000;
            sentinel::sdk::PluginSupervisor supervisor(host,
                                                       "/etc/sentinel/plugins.d",
                                                       "/etc/sentinel/rules.d",
                                                       "/etc/sentinel/wasm.d");
            supervisor.initialize();
            supervisor.print_status_table(std::cout);
            supervisor.shutdown();
            return 0;
        }

        if (cmd == "--generate-hardware-token")
        {
            std::cout << sentinel::licensing::LicenseManager::generate_hardware_token() << std::endl;
            return 0;
        }

        if (cmd == "--generate-ztp-token")
        {
            std::cout << sentinel::core::ZtpTokenAgent::instance().generate_provisioning_token() << std::endl;
            return 0;
        }

        if (cmd == "--subscribe" && argc >= 3)
        {
            std::string plan = argv[2];
            std::string url = (argc >= 4) ? argv[3] : "http://127.0.0.1:8000/api/v1";
            sentinel::licensing::LicenseManager::instance().subscribe_online(url, plan);
            return 0;
        }

        if (cmd == "--activate")
        {
            std::string url = (argc >= 3) ? argv[2] : "http://127.0.0.1:8000/api/v1";
            std::string token = (argc >= 4) ? argv[3] : "";
            sentinel::licensing::LicenseManager::instance().activate_online(url, token);
            return 0;
        }

        if (cmd == "--fetch-key")
        {
            std::string url = (argc >= 3) ? argv[2] : "http://127.0.0.1:8000/api/v1";
            sentinel::licensing::LicenseManager::instance().fetch_public_key_online(url);
            return 0;
        }
    }

    // Load cryptographic license envelope (/etc/sentinel/license.lic)
    sentinel::licensing::LicenseManager::instance().load_and_verify("/etc/sentinel/license.lic");
    std::cout << "[Sentinel Engine] Active Licensing Status: "
              << sentinel::licensing::LicenseManager::instance().get_tier_name() << std::endl;

    // Export local CycloneDX SBOM manifest
    sentinel::sbom::SbomScanner::instance().export_manifest("/etc/sentinel/sbom.json");

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "==========================================================" << std::endl;
    std::cout << "  BLACKBOX SENTINEL™ Cyber-Physical Threat Defense Node   " << std::endl;
    std::cout << "  Powered by libblackbox.so & libxinfer.so                " << std::endl;
    std::cout << "==========================================================" << std::endl;

    // 1. Hardware Identity & TPM 2.0 Validation
    sentinel::hardware::TPMLicenseValidator license_validator("DEVELOPMENT_MODE");
    license_validator.validate_license();

    try
    {
        // 2. Initialize Layer 2 Blackbox Security Engine
        std::cout << "[Blackbox Sentinel] Initializing libblackbox.so security engine..." << std::endl;
        blackbox::BlackboxEngine security_engine("configs/sentinel_config.json");
        security_engine.start();

        // 3. Initialize In-Kernel eBPF Drop Map Offload
        sentinel::nexus::KernelDropInjector::instance().initialize("/sys/fs/bpf/blackbox_blocked_ips");

        // 4. Initialize 3-Tier Extensibility Subsystem (Native C++20, LuaJIT, Wasm3)
        std::cout << "[Blackbox Sentinel] Initializing 3-Tier Extensibility Subsystem..." << std::endl;
        SentinelHostInterface plugin_host{};
        plugin_host.engine_version = 10000;
        plugin_host.log_message = [](int level, const char* sender, const char* msg) {
            const char* lvl_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};
            std::cout << "[" << lvl_str[level] << "] (" << sender << ") " << msg << std::endl;
        };
        plugin_host.request_ebpf_drop_ip = [](uint32_t ipv4, uint32_t duration_sec) -> int {
            return sentinel::nexus::KernelDropInjector::instance().inject_drop_ipv4(ipv4, duration_sec);
        };
        plugin_host.emit_metric_counter = [](const char* name, uint64_t val) {
            (void)name; (void)val;
        };
        plugin_host.get_monotonic_time_ns = []() -> uint64_t {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        };

        sentinel::sdk::PluginSupervisor plugin_supervisor(
            plugin_host,
            "/etc/sentinel/plugins.d",
            "/etc/sentinel/rules.d",
            "/etc/sentinel/wasm.d"
        );
        plugin_supervisor.initialize();

        std::cout << "[Blackbox Sentinel] Extensibility Subsystem Active: "
                  << plugin_supervisor.native_loader().active_plugin_count() << " Native | "
                  << plugin_supervisor.lua_engine().active_rule_count() << " Lua | "
                  << plugin_supervisor.wasm_sandbox().active_module_count() << " Wasm Sandboxed\n"
                  << std::endl;

        // 5. Bootstrap all 26 Modular Subsystems via Orchestrator
        sentinel::core::Orchestrator orchestrator;
        orchestrator.bootstrap_all_modules("configs/modules");

        // 6. Initialize REST Command Center & Web Server on Port 8443
        sentinel::api::RESTController api_server(8443, security_engine);
        api_server.start();

        // 7. Generate CMMC Audit Report
        sentinel::exporter::ReportGenerator::generate_cmmc_compliance_report("cmmc_audit_report.txt");

        std::cout << "[Blackbox Sentinel] Web Command Center live at: http://localhost:8443\n"
                  << std::endl;

        sentinel::nexus_client::NexusConfig n_cfg{
            .enabled = true,
            .host = "127.0.0.1",
            .port = 50051,
            .heartbeat_interval_sec = 5,
            .site_identifier = "Edge-Substation-01",
            .active_model_name = "network_threat_v1.onnx"};
        sentinel::nexus_client::NexusUplink::instance().start(n_cfg);

        // 8. Main Pipeline Event Ingestion Loop
        uint64_t counter = 0;
        while (g_appliance_running)
        {
            counter++;

            blackbox::SecurityEvent event;
            event.event_id = counter;
            event.timestamp = std::chrono::system_clock::now();
            event.type = blackbox::EventType::NetworkPacket;
            event.source_ip = "192.168.1." + std::to_string(100 + (counter % 30));
            event.features = {0.15f, 0.88f, (counter % 5 == 0 ? 0.95f : 0.1f), 0.2f};

            // Evaluate incoming frames across 3-tier extension pipeline (Native -> Lua -> Wasm)
            uint8_t dummy_frame[16] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01};
            SentinelRawPacket raw_pkt{
                .data = dummy_frame,
                .length = sizeof(dummy_frame),
                .timestamp_ns = plugin_host.get_monotonic_time_ns(),
                .ingress_ifindex = 1,
                .network_proto = 0x0800,
                .transport_proto = 6,
                .reserved = 0
            };

            auto ext_verdict = plugin_supervisor.evaluate_frame(raw_pkt);
            if (ext_verdict.verdict == SENTINEL_VERDICT_KERNEL_DROP) {
                // Instantly offloaded to kernel blocked_ip_map via request_ebpf_drop_ip
            }

            // Dispatch event across the EventBus to all 26 modules asynchronously
            sentinel::EventBus::instance().publish(event);

            // Submit event to core security engine
            security_engine.submit_event(event);

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        api_server.stop();
        plugin_supervisor.shutdown();
        orchestrator.shutdown_all_modules();
        security_engine.stop();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[Sentinel Appliance Error] " << e.what() << std::endl;
        return -1;
    }

    std::cout << "[Blackbox Sentinel] Service Stopped Gracefully." << std::endl;
    return 0;
}