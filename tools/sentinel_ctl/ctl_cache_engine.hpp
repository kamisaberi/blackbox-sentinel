#pragma once

#include "common_ctl.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_cache_list();
int cmd_cache_search(const std::string &query, const std::string &type_filter = "");
int cmd_cache_clean();
int cmd_cache_export(const std::string &out_tar);
int cmd_cache_import(const std::string &in_tar);

// [PLACEHOLDER: Full implementations of cmd_cache_* go here]