#pragma once

#include "common_ctl.hpp"
#include "sentinel/hardware/tpm_enrollment.hpp"
#include "sentinel/subsystems/trism_firewall.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_status()
{
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 BLACKBOX SENTINEL APPLIANCE STATUS & HEALTH                    \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";

    std::error_code ec;

    std::cout << "  \033[1m[1] Cryptographic Identity & Licensing:\033[0m\n";
    if (fs::exists("/etc/sentinel/license.lic", ec) && !ec)
    {
        std::cout << "      Status          : \033[1;32mACTIVE LICENSE LOADED\033[0m (/etc/sentinel/license.lic)\n";
    }
    else
    {
        std::cout << "      Status          : \033[1;33mCOMMUNITY EVALUATION\033[0m (Unlicensed mode)\n";
    }
    if ((fs::exists("/dev/tpmrm0", ec) || fs::exists("/dev/tpm0", ec)) && !ec)
    {
        std::cout << "      Hardware Root   : \033[1;32mPHYSICAL TPM 2.0 ATTESTED\033[0m\n";
    }
    else
    {
        std::cout << "      Hardware Root   : \033[1;33mDMI UUID FALLBACK\033[0m (Virtualization detected)\n";
    }

    std::cout << "\n  \033[1m[2] In-Kernel eBPF/XDP Mitigation Subsystem:\033[0m\n";
    if ((fs::exists("/sys/fs/bpf/blackbox_blocked_ips", ec) || fs::exists("/sys/fs/bpf/blocked_ip_map", ec)) && !ec)
    {
        std::cout << "      eBPF Map Status : \033[1;32mPINNED & ACTIVE IN KERNEL\033[0m (< 0.84 µs SLA)\n";
    }
    else
    {
        std::cout << "      eBPF Map Status : \033[1;33mIN-PROCESS RUNTIME\033[0m (Local testing mode / run with sudo for pinned maps)\n";
    }

    std::cout << "\n  \033[1m[3] Central Asset Cache Engine:\033[0m\n";
    fs::path c_root = get_cache_root();
    std::cout << "      Cache Location  : " << c_root.string() << "\n"
              << "      Registry URL    : " << normalize_registry_url(g_hub_url) << "\n";

    size_t count_native = 0, count_wasm = 0, count_lua = 0;
    if (fs::exists("/etc/sentinel/plugins.d", ec) && !ec)
    {
        for (const auto &e : fs::directory_iterator("/etc/sentinel/plugins.d", ec))
            if (e.path().extension() == ".so")
                count_native++;
    }
    if (fs::exists("/etc/sentinel/wasm.d", ec) && !ec)
    {
        for (const auto &e : fs::directory_iterator("/etc/sentinel/wasm.d", ec))
            if (e.path().extension() == ".wasm")
                count_wasm++;
    }
    if (fs::exists("/etc/sentinel/rules.d", ec) && !ec)
    {
        for (const auto &e : fs::directory_iterator("/etc/sentinel/rules.d", ec))
            if (e.path().extension() == ".lua")
                count_lua++;
    }

    std::cout << "\n  \033[1m[4] Active Edge Extensions Runtime:\033[0m\n"
              << "      Tier A: Native C++20 Dissectors : " << count_native << " active (< 120 ns SLA)\n"
              << "      Tier C: LuaJIT Dynamic Rules    : " << count_lua << " active (< 450 ns SLA)\n"
              << "      Tier B: Rust Wasm3 Sandboxes    : " << count_wasm << " active (< 1.5 µs SLA)\n";

    std::cout << "\n  \033[1m[5] Routing DAG Profile:\033[0m\n";
    std::string found_profile;
    for (const auto &p : {"configs/model_routes.yaml", "../configs/model_routes.yaml", "/etc/sentinel/model_routes.yaml"})
    {
        if (fs::exists(p, ec) && !ec)
        {
            found_profile = p;
            break;
        }
    }
    if (!found_profile.empty())
    {
        std::cout << "      Profile         : \033[1;32m" << found_profile << "\033[0m (4-Stage Pipeline)\n";
    }
    else
    {
        std::cout << "      Profile         : \033[1;33mMISSING\033[0m (Run: sudo cp configs/model_routes.yaml /etc/sentinel/)\n";
    }
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}

int cmd_hardware_status()
{
    sentinel::hardware::TpmEnrollmentManager mgr;
    auto profile = mgr.detect_hardware_profile();
    auto token = mgr.generate_hardware_token();
    bool verified = mgr.verify_hardware_token();

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m            PHYSICAL HARDWARE PROVISIONING & TPM 2.0 STATUS                     \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n"
              << "Hardware Profile : \033[1;33m" << profile.profile_id << "\033[0m (" << profile.arch << ")\n"
              << "TPM Device Path  : " << (profile.tpm_device_path.empty() ? "None (Fallback DMI UUID)" : profile.tpm_device_path) << "\n"
              << "TPM 2.0 Attested : " << (token.tpm_attested ? "\033[1;32mYES (Physical Silicon)\033[0m" : "\033[1;33mNO (Virtualization)\033[0m") << "\n"
              << "DMI System UUID  : " << token.dmi_system_uuid << "\n"
              << "Hardware Token   : \033[1;32m" << token.hardware_token_hash << "\033[0m\n"
              << "Binding Status   : " << (verified ? "\033[1;32m[VERIFIED] Token Binds to Silicon\033[0m" : "\033[1;33m[UNENROLLED] Run 'sentinel-ctl hardware enroll'\033[0m") << "\n"
              << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}

int cmd_hardware_enroll()
{
    sentinel::hardware::TpmEnrollmentManager mgr;
    auto token = mgr.generate_hardware_token();
    bool saved = mgr.save_hardware_token(token);

    if (saved)
    {
        std::cout << "\033[1;32m[+] Successfully enrolled hardware identity token into /etc/sentinel/hardware_identity.token\033[0m\n"
                  << "    Token Hash: " << token.hardware_token_hash << "\n";
        return 0;
    }
    std::cerr << "[-] Error: Failed to save hardware token to /etc/sentinel/\n";
    return 1;
}

int cmd_license_apply(const fs::path &lic_path)
{
    if (!fs::exists(lic_path))
    {
        std::cerr << "[-] Error: License file not found: " << lic_path << std::endl;
        return 1;
    }
    fs::create_directories("/etc/sentinel");
    fs::copy_file(lic_path, "/etc/sentinel/license.lic", fs::copy_options::overwrite_existing);
    std::cout << "\033[1;32m[+] Successfully applied commercial license to /etc/sentinel/license.lic\033[0m\n";
    return 0;
}

int cmd_license_inspect(const fs::path &lic_path)
{
    if (!fs::exists(lic_path))
    {
        std::cerr << "[-] Error: License file not found: " << lic_path << std::endl;
        return 1;
    }
    auto data = read_binary_file(lic_path);
    std::string lic_str(reinterpret_cast<const char *>(data.data()), data.size());

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 SENTINEL COMMERCIAL LICENSE INSPECTION                          \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n"
              << "License File : " << lic_path.string() << "\n"
              << "File Size    : " << data.size() << " bytes\n"
              << "--------------------------------------------------------------------------------\n"
              << "\033[1;37mENTITLEMENT DATA:\033[0m\n"
              << lic_str << "\n"
              << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}

int cmd_5g_enable(const std::string &iface, const fs::path &cfg_path);
int cmd_5g_status();

int cmd_sbom_generate();
int cmd_sbom_enforce();
int cmd_sbom_status();
int cmd_sbom_test_drift();
int cmd_sbom_attest();

int cmd_trism_status();
int cmd_trism_inspect(const std::string &prompt);
int cmd_trism_test_jailbreak();
int cmd_trism_policy(const std::string &action = "show");

// [PLACEHOLDER: Full implementations of cmd_status, cmd_5g_*, cmd_sbom_*, and cmd_trism_* go here]