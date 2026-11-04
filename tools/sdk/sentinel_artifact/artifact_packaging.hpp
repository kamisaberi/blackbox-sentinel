#pragma once

#include "common_artifact.hpp"

// --- FUNCTION PROTOTYPES ---
bool cmd_new(const std::string &name, std::string lang);
bool cmd_keygen(const std::string &prefix);
bool cmd_pack_raw(const std::string &priv_key_path, uint32_t tier, const std::string &manifest_path, const std::string &payload_path, const std::string &source_path, const std::string &test_pkt_path, const std::string &out_path);
bool cmd_pack_dir(const std::string &dir_str, const std::string &key_override = "");
bool cmd_inspect(const std::string &spkg_path);
bool cmd_verify(const std::string &pub_key_path, const std::string &spkg_path);
bool cmd_extract_source(const std::string &spkg_path, const std::string &out_source_file);
bool cmd_test_preflight(const std::string &spkg_path);

// [PLACEHOLDER: Implementations of cmd_new, cmd_keygen, cmd_pack_*, cmd_inspect, cmd_verify, cmd_extract_source, and cmd_test_preflight go here]