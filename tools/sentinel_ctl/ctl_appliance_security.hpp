#pragma once

#include "common_ctl.hpp"
#include "sentinel/hardware/tpm_enrollment.hpp"
#include "sentinel/subsystems/trism_firewall.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_status();
int cmd_hardware_status();
int cmd_hardware_enroll();
int cmd_license_apply(const fs::path &lic_path);
int cmd_license_inspect(const fs::path &lic_path);

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