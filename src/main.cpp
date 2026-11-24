// File: /home/kami/blackbox-sentinel/src/main.cpp

#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <string>
#include <filesystem>
#include <cstdlib>

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

// Extensibility, Ingress & eBPF Subsystem Headers
#include "sdk/PluginSupervisor.hpp"
#include "nexus/KernelDropInjector.hpp"
#include "ai/ModelRouter.hpp"
#include "sentinel/ingress/IngressManager.hpp"

std::atomic<bool> g_appliance_running{true};

void signal_handler(int sig)
{
    (void)sig;
    sentinel::nexus_client::NexusUplink::instance().stop();
    g_appliance_running = false;
}

void print_help(const char *prog_name)
{
    std::cout << "\033[36m\033[1m"
              << "==========================================================\n"
              << "  BLACKBOX SENTINEL™ Cyber-Physical Threat Defense Node   \n"
              << "  Powered by libblackbox.so & libxinfer.so                \n"
              << "==========================================================\033[0m\n\n"
              << "\033[1mUSAGE:\033[0m\n"
              << "  " << prog_name << " [OPTIONS]\n"
              << "  " << prog_name << " --routes <path_to_model_routes.yaml>\n"
              << "  " << prog_name << " [CONFIG_FILE]\n\n"
              << "\033[1mCORE APPLIANCE OPTIONS:\033[0m\n"
              << "  \033[32m-h, --help\033[0m\n"
              << "      Show this help menu and exit.\n\n"
              << "  \033[32m-r, --routes <path.yaml>\033[0m\n"
              << "      Specify custom sensor routing & AI model pipeline configuration.\n"
              << "      Default: \033[33mconfigs/model_routes.yaml\033[0m\n\n"

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
              << "    5. Loads Sensor-to-Model Routing DAG from \033[33mconfigs/model_routes.yaml\033[0m.\n"
              << "    6. Launches local Web Command Center on port \033[34m8443\033[0m.\n"
              << "    7. Connects NexusUplink gRPC client to Sentinel Nexus (\033[34m50051\033[0m).\n\n"

              << "\033[1mEXAMPLES:\033[0m\n"
              << "  sudo " << prog_name << " --help\n"
              << "  sudo " << prog_name << " --routes configs/model_routes.yaml\n"
              << "  sudo " << prog_name << " -r /etc/sentinel/profiles/substation_east.yaml\n"
              << "  sudo " << prog_name << " --plugins-status\n"
              << "  sudo " << prog_name << " --generate-hardware-token\n"
              << "  sudo " << prog_name << " --subscribe community http://127.0.0.1:8000/api/v1\n"
              << "  sudo " << prog_name << " --activate http://127.0.0.1:8000/api/v1 \"eyJh...\"\n"
              << std::endl;
}



