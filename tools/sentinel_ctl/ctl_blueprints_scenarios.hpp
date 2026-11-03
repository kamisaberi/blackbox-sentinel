#pragma once

#include "common_ctl.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_scenario_new(const std::string &name, const std::string &sector_override = "");
int cmd_scenario_add(const std::string &scenario_dir_str, const std::string &asset_id, bool embed_binary = false);
int cmd_scenario_pack(const std::string &dir_str, const std::string &out_override = "", bool embed = false);
int cmd_scenario_pull(const std::string &slug);
int cmd_scenario_list();

int cmd_blueprint_new(const std::string &name, const std::string &site_override = "");
int cmd_blueprint_add(const std::string &bp_dir_str, const std::string &asset_id, bool embed_binary = false);
int cmd_blueprint_pack(const std::string &dir_str, const std::string &out_override = "", bool embed = false);
int cmd_blueprint_inspect(const std::string &target_str);
int cmd_blueprint_deploy(const std::string &target_str);
int cmd_blueprint_rollback();
int cmd_blueprint_list();

// [PLACEHOLDER: Full implementations of cmd_scenario_* and cmd_blueprint_* go here]