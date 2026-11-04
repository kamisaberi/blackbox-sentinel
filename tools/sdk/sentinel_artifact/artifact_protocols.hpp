#pragma once

#include "common_artifact.hpp"
#include "artifact_packaging.hpp"

// --- FUNCTION PROTOTYPES ---
bool cmd_slab_convert(const std::string &in_csv_path, const std::string &out_slab_path, uint32_t expected_dim);
bool cmd_slab_verify(const std::string &slab_path);
bool cmd_pcap_pack(const std::string &priv_key_path, const std::string &manifest_path, const std::string &in_pcap_path, const std::string &out_spcap_path);
bool cmd_synthesize_vaccine(const std::string &input_target, const std::string &out_dir_override = "");

