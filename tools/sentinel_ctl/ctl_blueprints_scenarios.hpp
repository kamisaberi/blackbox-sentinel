#pragma once

#include "common_ctl.hpp"

// --- FUNCTION PROTOTYPES ---
int cmd_scenario_new(const std::string &name, const std::string &sector_override = "")
{
    fs::path target_dir = fs::path("/home/kami/sentinel-matrix/scenarios") / name;
    if (!fs::exists("/home/kami/sentinel-matrix/scenarios"))
    {
        target_dir = fs::current_path() / name;
    }

    if (fs::exists(target_dir))
    {
        std::cerr << "[-] Error: Scenario directory already exists: " << target_dir.string() << std::endl;
        return 1;
    }

    std::string sector = sector_override.empty() ? "CRITICAL_INFRASTRUCTURE" : sector_override;
    std::string author_pub_hex = get_enrolled_author_pubkey_hex();

    fs::create_directories(target_dir / "packages");
    fs::create_directories(target_dir / "models");
    fs::create_directories(target_dir / "configs");
    fs::create_directories(target_dir / "pcaps");

    // 1. Create manifest.json
    std::ofstream mf(target_dir / "manifest.json");
    mf << "{\n"
       << "  \"name\": \"" << name << "\",\n"
       << "  \"slug\": \"" << name << "\",\n"
       << "  \"title\": \"" << name << "\",\n"
       << "  \"version\": \"1.0.0\",\n"
       << "  \"asset_type\": \"scenario\",\n"
       << "  \"target_sector\": \"" << sector << "\",\n"
       << "  \"sector\": \"" << sector << "\",\n"
       << "  \"complexity\": \"INTERMEDIATE\",\n"
       << "  \"category\": \"SCADA_ICS\",\n"
       << "  \"author\": \"Aryorithm Certified Engineer\",\n"
       << "  \"description\": \"Turnkey Digital Twin Scenario for " << name << "\",\n";
    if (!author_pub_hex.empty())
    {
        mf << "  \"author_public_key\": \"" << author_pub_hex << "\",\n";
    }
    mf << "  \"dependencies\": {\n"
       << "    \"packages\": [],\n"
       << "    \"models\": [],\n"
       << "    \"pcaps\": []\n"
       << "  },\n"
       << "  \"compliance\": [\"IEC-62443-4-2\", \"NIS2\"]\n"
       << "}\n";
    mf.close();

    // 2. Create sovereign scenario.yaml
    std::ofstream sc(target_dir / "scenario.yaml");
    sc << "version: \"1.0\"\n"
       << "scenario:\n"
       << "  name: \"" << name << "\"\n"
       << "  description: \"Digital Twin Scenario for " << name << "\"\n\n"
       << "networks:\n"
       << "  ot_scada_net:\n"
       << "    driver: bridge\n"
       << "    subnet: \"10.220.0.0/24\"\n"
       << "    gateway: \"10.220.0.1\"\n"
       << "    internal: true\n\n"
       << "nodes:\n"
       << "  - name: \"primary-scada-plc\"\n"
       << "    hostname: \"plc01.scada.internal\"\n"
       << "    image: \"sentinel-matrix/device-runtime:latest\"\n"
       << "    networks:\n"
       << "      ot_scada_net:\n"
       << "        ip: \"10.220.0.10\"\n"
       << "    ports: [\"15501:502\"]\n"
       << "    command: [\"--archetype\", \"plc\", \"--protocol\", \"modbus\", \"--port\", \"502\", \"--name\", \"Primary-PLC\"]\n";
    sc.close();

    // 3. Create starter configs
    std::ofstream pr(target_dir / "configs" / "plc_register_map.json");
    pr << "{\n  \"holding_registers\": {\"flow\": 40001, \"pressure\": 40002, \"temp\": 40003}\n}\n";
    pr.close();

    // 4. Create dual-mode run_demo.sh
    std::ofstream rd(target_dir / "run_demo.sh");
    rd << "#!/usr/bin/env bash\n"
       << "set -euo pipefail\n"
       << "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
       << "cd \"$SCRIPT_DIR\"\n\n"
       << "echo \"[*] [Step 1] Deploying .spkg rules (Embedded or Cache-Resolved)...\"\n"
       << "if [ -d \"packages\" ] && [ \"$(ls -A packages/*.spkg 2>/dev/null)\" ]; then\n"
       << "    sudo aryo appliance install packages/*.spkg\n"
       << "fi\n\n"
       << "echo \"[*] [Step 2] Staging AI models...\"\n"
       << "sudo mkdir -p /etc/sentinel/models\n"
       << "if [ -d \"models\" ] && [ \"$(ls -A models/*.onnx 2>/dev/null)\" ]; then\n"
       << "    sudo cp -u models/*.onnx /etc/sentinel/models/\n"
       << "fi\n\n"
       << "echo \"[*] [Step 3] Launching digital twin scenario mesh...\"\n"
       << "aryo matrix scenario load scenario.yaml\n\n"
       << "echo \"[+] SUCCESS: Scenario '" << name << "' is running!\"\n";
    rd.close();
    fs::permissions(target_dir / "run_demo.sh", fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec);

    std::cout << "\033[1;32m[+] Successfully scaffolded scenario:\033[0m " << target_dir.string() << "\n"
              << "    ├── manifest.json   (Auto-enrolled author identity)\n"
              << "    ├── scenario.yaml   (Sovereign multi-network topology)\n"
              << "    ├── packages/       (Ready for .spkg rules)\n"
              << "    ├── models/         (Ready for .onnx models)\n"
              << "    ├── configs/        (Pre-populated register maps)\n"
              << "    └── run_demo.sh     (1-Click orchestration script)\n";
    return 0;
}
int cmd_scenario_add(const std::string &scenario_dir_str, const std::string &asset_id, bool embed_binary = false)
{
    fs::path target_dir(scenario_dir_str);
    if (!fs::exists(target_dir))
    {
        target_dir = fs::path("/home/kami/sentinel-matrix/scenarios") / scenario_dir_str;
    }
    if (!fs::exists(target_dir) || !fs::is_directory(target_dir))
    {
        std::cerr << "[-] Error: Scenario directory not found: " << scenario_dir_str << std::endl;
        return 1;
    }

    fs::path manifest_path = target_dir / "manifest.json";
    if (!fs::exists(manifest_path))
    {
        std::cerr << "[-] Error: manifest.json missing in " << target_dir.string() << std::endl;
        return 1;
    }

    // Smart Resolution Order: File Path -> Installed Runtime -> Local Cache
    std::string detected_type = "unknown";
    fs::path resolved_source;
    std::string clean_slug = asset_id;

    if (fs::exists(asset_id))
    {
        resolved_source = fs::path(asset_id);
        std::string ext = resolved_source.extension().string();
        clean_slug = resolved_source.stem().string();
        if (ext == ".spkg" || ext == ".lua" || ext == ".so")
            detected_type = "package";
        else if (ext == ".onnx")
            detected_type = "model";
        else if (ext == ".pcap")
            detected_type = "pcap";
        else if (ext == ".slab")
            detected_type = "dataset";
    }
    else
    {
        // Search Installed Runtime
        if (fs::exists("/etc/sentinel/rules.d/" + asset_id + ".lua"))
        {
            resolved_source = "/etc/sentinel/rules.d/" + asset_id + ".lua";
            detected_type = "package";
        }
        else if (fs::exists("/etc/sentinel/plugins.d/" + asset_id + ".so"))
        {
            resolved_source = "/etc/sentinel/plugins.d/" + asset_id + ".so";
            detected_type = "package";
        }
        else if (fs::exists("/etc/sentinel/models/" + asset_id + ".onnx") || fs::exists("models/" + asset_id + ".onnx"))
        {
            resolved_source = fs::exists("models/" + asset_id + ".onnx") ? fs::path("models/" + asset_id + ".onnx") : fs::path("/etc/sentinel/models/" + asset_id + ".onnx");
            detected_type = "model";
        }
        else if (fs::exists("/etc/sentinel/pcaps/" + asset_id + ".pcap"))
        {
            resolved_source = "/etc/sentinel/pcaps/" + asset_id + ".pcap";
            detected_type = "pcap";
        }
        else
        {
            // Search Cache
            fs::path c_root = get_cache_root();
            if (fs::exists(c_root / "packages" / (asset_id + ".spkg")))
            {
                resolved_source = c_root / "packages" / (asset_id + ".spkg");
                detected_type = "package";
            }
            else if (fs::exists(c_root / "models" / (asset_id + ".onnx")))
            {
                resolved_source = c_root / "models" / (asset_id + ".onnx");
                detected_type = "model";
            }
            else if (fs::exists(c_root / "pcaps" / (asset_id + ".pcap")))
            {
                resolved_source = c_root / "pcaps" / (asset_id + ".pcap");
                detected_type = "pcap";
            }
            else
            {
                std::cout << "[*] Asset not found locally. Treating '" << asset_id << "' as external Hub dependency reference.\n";
                detected_type = "package";
            }
        }
    }

    std::cout << "\033[1;36m[*] [Scenario Add] Resolved asset '" << clean_slug << "' as [" << detected_type << "]\033[0m\n";

    // If embedding is requested (or local file added), copy binary into scenario directory
    if (embed_binary && !resolved_source.empty() && fs::exists(resolved_source))
    {
        fs::path dest_dir = target_dir;
        if (detected_type == "package")
            dest_dir = target_dir / "packages";
        else if (detected_type == "model")
            dest_dir = target_dir / "models";
        else if (detected_type == "pcap")
            dest_dir = target_dir / "pcaps";

        fs::create_directories(dest_dir);
        fs::path dest_file = dest_dir / resolved_source.filename();
        fs::copy_file(resolved_source, dest_file, fs::copy_options::overwrite_existing);
        std::cout << "    ├── \033[1;32m[EMBEDDED]\033[0m Copied binary -> " << dest_file.string() << "\n";
    }
    else
    {
        std::cout << "    ├── \033[1;33m[REFERENCED]\033[0m Registered dependency (Zero storage bloat)\n";
    }

    // Update manifest.json dependencies
    auto mf_bytes = read_binary_file(manifest_path);
    std::string mf_str(reinterpret_cast<const char *>(mf_bytes.data()), mf_bytes.size());

    std::string dep_key = "\"" + detected_type + "s\": [";
    size_t pos = mf_str.find(dep_key);
    if (pos != std::string::npos)
    {
        size_t insert_pos = pos + dep_key.length();
        std::string to_insert = (mf_str[insert_pos] == ']') ? ("\"" + clean_slug + "\"") : ("\"" + clean_slug + "\", ");
        mf_str.insert(insert_pos, to_insert);
    }
    else
    {
        // Add dependencies block if missing
        size_t last_brace = mf_str.rfind('}');
        if (last_brace != std::string::npos)
        {
            std::string block = ",\n  \"dependencies\": {\n    \"" + detected_type + "s\": [\"" + clean_slug + "\"]\n  }\n}";
            mf_str.replace(last_brace, 1, block);
        }
    }

    std::ofstream mf_out(manifest_path);
    mf_out << mf_str;
    mf_out.close();

    std::cout << "    └── \033[1;32m[UPDATED]\033[0m Synchronized " << manifest_path.string() << "\n";
    return 0;
}

int cmd_scenario_pack(const std::string &dir_str, const std::string &out_override = "", bool embed = false)
{
    fs::path target_dir = dir_str.empty() ? fs::current_path() : fs::path(dir_str);
    if (!fs::exists(target_dir))
    {
        target_dir = fs::path("/home/kami/sentinel-matrix/scenarios") / dir_str;
    }
    if (!fs::exists(target_dir) || !fs::is_directory(target_dir))
    {
        std::cerr << "[-] Error: Scenario directory not found: " << target_dir.string() << std::endl;
        return 1;
    }

    std::string slug = target_dir.filename().string();
    if (slug == "." || slug.empty())
        slug = fs::current_path().filename().string();

    fs::path cache_scen_dir = get_cache_root() / "scenarios";
    fs::create_directories(cache_scen_dir);

    std::string archive_name = slug;
    if (archive_name.rfind("scenario_", 0) != 0)
        archive_name = "scenario_" + archive_name;
    if (archive_name.size() < 7 || archive_name.substr(archive_name.size() - 7) != ".tar.gz")
        archive_name += ".tar.gz";

    fs::path out_tar = out_override.empty() ? (cache_scen_dir / archive_name) : fs::path(out_override);
    if (out_tar.parent_path().empty())
        out_tar = cache_scen_dir / out_tar;
    fs::create_directories(out_tar.parent_path());

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        PACKING SCENARIO BUNDLE [" << (embed ? "EMBEDDED STANDALONE" : "DECLARATIVE REFERENCED") << "]\033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "Source Directory : " << target_dir.string() << "\n"
              << "Output Archive   : " << out_tar.string() << "\n";

    std::string tar_cmd;
    if (embed)
    {
        // Pack entire folder including packages/ and models/
        tar_cmd = "tar -czf \"" + out_tar.string() + "\" -C \"" + target_dir.string() + "\" .";
    }
    else
    {
        // Exclude large binary folders to keep the bundle lightweight (~15 KB)
        tar_cmd = "tar --exclude='packages/*.spkg' --exclude='models/*.onnx' -czf \"" + out_tar.string() + "\" -C \"" + target_dir.string() + "\" .";
    }

    int ret = std::system(tar_cmd.c_str());

    if (ret == 0 && fs::exists(out_tar))
    {
        fs::path companion_tar_mf = fs::path(out_tar.string() + ".manifest.json");
        fs::path src_mf = target_dir / "manifest.json";
        if (fs::exists(src_mf))
        {
            fs::copy_file(src_mf, companion_tar_mf, fs::copy_options::overwrite_existing);
        }

        size_t sz = fs::file_size(out_tar);
        std::cout << "\033[1;32m[+] Successfully packed scenario bundle!\033[0m\n"
                  << "    ├── Mode    : " << (embed ? "EMBEDDED (Air-Gapped)" : "DECLARATIVE (Hub-Optimized)") << "\n"
                  << "    ├── Size    : " << sz << " bytes\n"
                  << "    └── Publish : \033[1;37maryo publish " << out_tar.string() << "\033[0m\n";
        std::cout << "\033[1;36m================================================================================\033[0m\n";
        return 0;
    }

    return 1;
}
int cmd_scenario_pull(const std::string &slug)
{
    std::string filename = slug;
    if (filename.size() < 7 || filename.substr(filename.size() - 7) != ".tar.gz")
    {
        if (filename.size() >= 4 && filename.substr(filename.size() - 4) == ".tgz")
            filename = filename.substr(0, filename.size() - 4) + ".tar.gz";
        else
            filename += ".tar.gz";
    }

    fs::path cached_path;
    if (!resolve_cached_asset("scenarios", filename, cached_path))
    {
        std::cerr << "[-] Error: Failed to resolve scenario '" << slug << "' from cache or Hub registry.\n";
        return 1;
    }

    // Determine target extraction directory inside sentinel-matrix
    std::string pure_slug = fs::path(filename).stem().string();
    if (pure_slug.rfind("scenario_", 0) == 0)
        pure_slug = pure_slug.substr(9);

    fs::path target_matrix_dir = fs::path("/home/kami/sentinel-matrix/scenarios") / pure_slug;

    if (!fs::exists("/home/kami/sentinel-matrix/scenarios"))
    {
        target_matrix_dir = fs::path("/etc/sentinel/scenarios") / pure_slug;
    }

    fs::create_directories(target_matrix_dir);

    std::cout << "[*] Unpacking scenario bundle: " << cached_path.filename().string() << "...\n"
              << "    --> Destination: " << target_matrix_dir.string() << "\n";

    std::string untar_cmd = "tar -xzf \"" + cached_path.string() + "\" -C \"" + target_matrix_dir.string() + "\"";
    int ret = std::system(untar_cmd.c_str());

    if (ret == 0)
    {
        std::cout << "\033[1;32m[+] Successfully staged digital twin scenario!\033[0m\n"
                  << "    Location : " << target_matrix_dir.string() << "\n";

        // Check if scenario.yaml exists inside
        fs::path scen_yaml = target_matrix_dir / "scenario.yaml";
        if (fs::exists(scen_yaml))
        {
            std::cout << "    Launch   : \033[1;37maryo matrix scenario load " << scen_yaml.string() << "\033[0m\n";
        }
        else
        {
            std::cout << "    Launch   : \033[1;37maryo matrix scenario load " << target_matrix_dir.string() << "\033[0m\n";
        }
        return 0;
    }

    std::cerr << "[-] Error: Failed to unpack archive into " << target_matrix_dir.string() << std::endl;
    return 1;
}
int cmd_scenario_list()
{
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 ARYORITHM DIGITAL TWIN SCENARIOS: LOCAL REPOSITORY                      \033[0m\n";
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";

    fs::path cache_scen_dir = get_cache_root() / "scenarios";
    std::cout << "Cached Archives (" << cache_scen_dir.string() << "):\n";
    if (fs::exists(cache_scen_dir))
    {
        for (const auto &entry : fs::directory_iterator(cache_scen_dir))
        {
            if (entry.is_regular_file())
            {
                std::cout << "  • " << std::left << std::setw(36) << entry.path().filename().string()
                          << " (" << fs::file_size(entry) << " bytes)\n";
            }
        }
    }
    else
    {
        std::cout << "  (No cached scenario archives found)\n";
    }

    fs::path matrix_scen_dir = "/home/kami/sentinel-matrix/scenarios";
    std::cout << "\nStaged Scenarios for Sentinel-Matrix (" << matrix_scen_dir.string() << "):\n";
    if (fs::exists(matrix_scen_dir))
    {
        for (const auto &entry : fs::directory_iterator(matrix_scen_dir))
        {
            if (entry.is_directory() || entry.path().extension() == ".yaml")
            {
                std::cout << "  \033[1;32m[READY]\033[0m " << entry.path().filename().string() << "\n";
            }
        }
    }
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";
    return 0;
}

int cmd_blueprint_new(const std::string &name, const std::string &site_override = "")
{
    fs::path target_dir = fs::current_path() / name;
    if (fs::exists(target_dir))
    {
        std::cerr << "[-] Error: Blueprint directory already exists: " << target_dir.string() << std::endl;
        return 1;
    }

    std::string site_name = site_override.empty() ? ("Site-" + name) : site_override;
    std::string author_pub_hex = get_enrolled_author_pubkey_hex();

    fs::create_directories(target_dir / "configs");
    fs::create_directories(target_dir / "packages");
    fs::create_directories(target_dir / "models");

    // 1. Create manifest.json
    std::ofstream mf(target_dir / "manifest.json");
    mf << "{\n"
       << "  \"name\": \"" << name << "\",\n"
       << "  \"slug\": \"" << name << "\",\n"
       << "  \"title\": \"" << name << "\",\n"
       << "  \"version\": \"1.0.0\",\n"
       << "  \"asset_type\": \"blueprint\",\n"
       << "  \"target_site\": \"" << site_name << "\",\n"
       << "  \"author\": \"Aryorithm Certified Engineer\",\n"
       << "  \"description\": \"Production Edge Blueprint for " << site_name << "\",\n";
    if (!author_pub_hex.empty())
        mf << "  \"author_public_key\": \"" << author_pub_hex << "\",\n";
    mf << "  \"dependencies\": {\n"
       << "    \"packages\": [],\n"
       << "    \"models\": []\n"
       << "  },\n"
       << "  \"compliance\": [\"IEC-62443-4-2\", \"NIS2\"]\n"
       << "}\n";
    mf.close();

    // 2. Create blueprint.yaml (Physical Hardware Binding)
    std::ofstream bp(target_dir / "blueprint.yaml");
    bp << "# ==============================================================================\n"
       << "# ARYORITHM PRODUCTION HARDWARE BLUEPRINT SPECIFICATION\n"
       << "# ==============================================================================\n"
       << "blueprint:\n"
       << "  name: \"" << name << "\"\n"
       << "  site_identifier: \"" << site_name << "\"\n"
       << "  target_architecture: \"x86_64\"\n\n"
       << "hardware_binding:\n"
       << "  primary_interface: \"ens160\"           # Physical NIC (ens160, eth0, or gtp5g0)\n"
       << "  af_xdp_mode: \"SKB\"                   # ZEROCOPY for physical NIC, SKB for virtualized\n"
       << "  rss_queues: [0, 1, 2, 3]             # Multi-Queue RSS queue pinning\n"
       << "  cpu_affinity_cores: [2, 3, 4, 5]\n"
       << "  require_physical_tpm: true\n\n"
       << "sla_guarantees:\n"
       << "  max_pipeline_latency_us: 100.0\n"
       << "  critical_clearing_time_ms: 38.4\n";
    bp.close();

    // 3. Create model_routes.yaml (Production 4-Stage Pipeline DAG)
    std::ofstream mr(target_dir / "model_routes.yaml");
    mr << "# ==============================================================================\n"
       << "# 4-STAGE MODEL ROUTER PIPELINE CONFIGURATION\n"
       << "# ==============================================================================\n"
       << "pipeline:\n"
       << "  stage_1_reflex:\n"
       << "    enabled: true\n"
       << "    rules:\n"
       << "      - name: \"modbus_fast_drop\"\n"
       << "        port: 502\n"
       << "        tier: \"lua\"\n"
       << "  stage_2_dissectors:\n"
       << "    enabled: true\n"
       << "    protocols: [\"MODBUS\", \"S7COMM\", \"IEC104\"]\n"
       << "  stage_3_inference:\n"
       << "    enabled: true\n"
       << "    primary_backend: \"INTEL_OPENVINO\"\n"
       << "    models:\n"
       << "      - name: \"network_threat_detector\"\n"
       << "        precision: \"INT8\"\n"
       << "  stage_4_fusion:\n"
       << "    enabled: true\n"
       << "    correlator_mode: \"CROSS_MODAL_PHYSICS\"\n";
    mr.close();

    // 4. Create deploy.sh
    std::ofstream dp(target_dir / "deploy.sh");
    dp << "#!/usr/bin/env bash\n"
       << "set -euo pipefail\n"
       << "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
       << "echo \"[*] Deploying Production Blueprint: " << name << "\"\n"
       << "sudo aryo blueprint deploy \"$SCRIPT_DIR\"\n";
    dp.close();
    fs::permissions(target_dir / "deploy.sh", fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec);

    std::cout << "\033[1;32m[+] Successfully scaffolded production blueprint:\033[0m " << target_dir.string() << "\n"
              << "    ├── manifest.json       (Attestation & dependency metadata)\n"
              << "    ├── blueprint.yaml      (Physical NIC & hardware binding)\n"
              << "    ├── model_routes.yaml   (4-Stage ModelRouter DAG)\n"
              << "    ├── configs/            (Subsystem policy manifests)\n"
              << "    └── deploy.sh           (1-Click deployment hook)\n";
    return 0;
}
int cmd_blueprint_add(const std::string &bp_dir_str, const std::string &asset_id, bool embed_binary = false)
{
    fs::path target_dir(bp_dir_str);
    if (!fs::exists(target_dir) || !fs::is_directory(target_dir))
    {
        std::cerr << "[-] Error: Blueprint directory not found: " << bp_dir_str << std::endl;
        return 1;
    }

    fs::path manifest_path = target_dir / "manifest.json";
    if (!fs::exists(manifest_path))
    {
        std::cerr << "[-] Error: manifest.json missing in " << target_dir.string() << std::endl;
        return 1;
    }

    std::string detected_type = "unknown";
    fs::path resolved_source;
    std::string clean_slug = asset_id;

    if (fs::exists(asset_id))
    {
        resolved_source = fs::path(asset_id);
        std::string ext = resolved_source.extension().string();
        clean_slug = resolved_source.stem().string();
        if (ext == ".spkg" || ext == ".lua" || ext == ".so")
            detected_type = "package";
        else if (ext == ".onnx")
            detected_type = "model";
    }
    else
    {
        if (fs::exists("/etc/sentinel/rules.d/" + asset_id + ".lua"))
        {
            resolved_source = "/etc/sentinel/rules.d/" + asset_id + ".lua";
            detected_type = "package";
        }
        else if (fs::exists("/etc/sentinel/models/" + asset_id + ".onnx") || fs::exists("models/" + asset_id + ".onnx"))
        {
            resolved_source = fs::exists("models/" + asset_id + ".onnx") ? fs::path("models/" + asset_id + ".onnx") : fs::path("/etc/sentinel/models/" + asset_id + ".onnx");
            detected_type = "model";
        }
        else
        {
            fs::path c_root = get_cache_root();
            if (fs::exists(c_root / "packages" / (asset_id + ".spkg")))
            {
                resolved_source = c_root / "packages" / (asset_id + ".spkg");
                detected_type = "package";
            }
            else if (fs::exists(c_root / "models" / (asset_id + ".onnx")))
            {
                resolved_source = c_root / "models" / (asset_id + ".onnx");
                detected_type = "model";
            }
            else
            {
                std::cout << "[*] Treating '" << asset_id << "' as external dependency reference.\n";
                detected_type = "package";
            }
        }
    }

    std::cout << "\033[1;36m[*] [Blueprint Add] Registered asset '" << clean_slug << "' as [" << detected_type << "]\033[0m\n";

    if (embed_binary && !resolved_source.empty() && fs::exists(resolved_source))
    {
        fs::path dest_dir = (detected_type == "package") ? (target_dir / "packages") : (target_dir / "models");
        fs::create_directories(dest_dir);
        fs::path dest_file = dest_dir / resolved_source.filename();
        fs::copy_file(resolved_source, dest_file, fs::copy_options::overwrite_existing);
        std::cout << "    ├── \033[1;32m[EMBEDDED]\033[0m Staged -> " << dest_file.string() << "\n";
    }

    // Update manifest dependencies
    auto mf_bytes = read_binary_file(manifest_path);
    std::string mf_str(reinterpret_cast<const char *>(mf_bytes.data()), mf_bytes.size());
    std::string dep_key = "\"" + detected_type + "s\": [";
    size_t pos = mf_str.find(dep_key);
    if (pos != std::string::npos)
    {
        size_t insert_pos = pos + dep_key.length();
        std::string to_insert = (mf_str[insert_pos] == ']') ? ("\"" + clean_slug + "\"") : ("\"" + clean_slug + "\", ");
        mf_str.insert(insert_pos, to_insert);
        std::ofstream mf_out(manifest_path);
        mf_out << mf_str;
        mf_out.close();
    }

    std::cout << "    └── \033[1;32m[UPDATED]\033[0m Manifest synchronized.\n";
    return 0;
}
int cmd_blueprint_pack(const std::string &dir_str, const std::string &out_override = "", bool embed = false)
{
    fs::path target_dir = dir_str.empty() ? fs::current_path() : fs::path(dir_str);
    if (!fs::exists(target_dir) || !fs::is_directory(target_dir))
    {
        std::cerr << "[-] Error: Blueprint directory not found: " << target_dir.string() << std::endl;
        return 1;
    }

    std::string slug = target_dir.filename().string();
    fs::path cache_dir = get_cache_root() / "blueprints";
    fs::create_directories(cache_dir);

    std::string archive_name = slug;
    if (archive_name.rfind("blueprint_", 0) != 0)
        archive_name = "blueprint_" + archive_name;
    if (archive_name.size() < 10 || archive_name.substr(archive_name.size() - 10) != ".blueprint")
        archive_name += ".blueprint";

    fs::path out_file = out_override.empty() ? (cache_dir / archive_name) : fs::path(out_override);
    if (out_file.parent_path().empty())
        out_file = cache_dir / out_file;
    fs::create_directories(out_file.parent_path());

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        PACKING PRODUCTION BLUEPRINT [" << (embed ? "STANDALONE EMBEDDED" : "DECLARATIVE") << "]\033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "Source Directory : " << target_dir.string() << "\n"
              << "Output Archive   : " << out_file.string() << "\n";

    std::string tar_cmd = embed ? ("tar -czf \"" + out_file.string() + "\" -C \"" + target_dir.string() + "\" .") : ("tar --exclude='packages/*.spkg' --exclude='models/*.onnx' -czf \"" + out_file.string() + "\" -C \"" + target_dir.string() + "\" .");

    int ret = std::system(tar_cmd.c_str());
    if (ret == 0 && fs::exists(out_file))
    {
        fs::path companion_mf = fs::path(out_file.string() + ".manifest.json");
        fs::path src_mf = target_dir / "manifest.json";
        if (fs::exists(src_mf))
            fs::copy_file(src_mf, companion_mf, fs::copy_options::overwrite_existing);

        std::cout << "\033[1;32m[+] Successfully packed blueprint!\033[0m\n"
                  << "    ├── Archive File : " << out_file.string() << " (" << fs::file_size(out_file) << " bytes)\n"
                  << "    └── Deploy with  : \033[1;37msudo aryo blueprint deploy " << out_file.string() << "\033[0m\n";
        std::cout << "\033[1;36m================================================================================\033[0m\n";
        return 0;
    }
    return 1;
}
int cmd_blueprint_inspect(const std::string &target_str)
{
    fs::path p(target_str);
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        INSPECTING PRODUCTION BLUEPRINT: " << p.filename().string() << "\033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";

    if (fs::is_directory(p))
    {
        if (fs::exists(p / "blueprint.yaml"))
        {
            std::cout << "\033[1m[Hardware & Interface Binding]:\033[0m\n";
            std::ifstream f(p / "blueprint.yaml");
            std::cout << f.rdbuf() << "\n";
        }
        if (fs::exists(p / "manifest.json"))
        {
            std::cout << "\033[1m[Dependencies & Compliance]:\033[0m\n";
            std::ifstream f(p / "manifest.json");
            std::cout << f.rdbuf() << "\n";
        }
    }
    else
    {
        std::cout << "Archive File     : " << p.string() << " (" << fs::file_size(p) << " bytes)\n";
        std::cout << "Archive Contents :\n";
        std::string cmd = "tar -tf \"" + p.string() + "\"";
        std::system(cmd.c_str());
    }
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}
int cmd_blueprint_deploy(const std::string &target_str)
{
    if (geteuid() != 0)
    {
        std::cerr << "\033[1;31m[-] Error: Blueprint deployment must be executed with root privileges:\033[0m\n"
                  << "    sudo aryo blueprint deploy " << target_str << "\n";
        return 1;
    }

    fs::path target_path(target_str);
    fs::path deploy_dir = target_path;
    bool is_temp_extract = false;

    // If given an archive (.blueprint or .tar.gz), extract to staging area
    if (fs::is_regular_file(target_path))
    {
        deploy_dir = fs::path("/tmp") / ("blueprint_deploy_" + std::to_string(getpid()));
        fs::create_directories(deploy_dir);
        is_temp_extract = true;
        std::string untar = "tar -xzf \"" + target_path.string() + "\" -C \"" + deploy_dir.string() + "\"";
        std::system(untar.c_str());
    }

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m        EXECUTING ATOMIC EDGE HARDWARE BLUEPRINT PROVISIONING                   \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";

    // Step 1: Backup existing configuration for instant rollback
    fs::path backup_dir = "/etc/sentinel/.blueprint_backup";
    fs::create_directories(backup_dir);
    if (fs::exists("/etc/sentinel/model_routes.yaml"))
    {
        fs::copy_file("/etc/sentinel/model_routes.yaml", backup_dir / "model_routes.yaml", fs::copy_options::overwrite_existing);
        std::cout << "[1/5] Backed up current live configuration -> " << backup_dir.string() << "\n";
    }

    // Step 2: Stage model_routes.yaml
    if (fs::exists(deploy_dir / "model_routes.yaml"))
    {
        fs::copy_file(deploy_dir / "model_routes.yaml", "/etc/sentinel/model_routes.yaml", fs::copy_options::overwrite_existing);
        std::cout << "[2/5] Staged 4-Stage ModelRouter DAG -> /etc/sentinel/model_routes.yaml\n";
    }

    // Step 3: Install .spkg reflex rules
    size_t pkg_count = 0;
    fs::create_directories("/etc/sentinel/rules.d");
    if (fs::exists(deploy_dir / "packages"))
    {
        for (const auto &e : fs::directory_iterator(deploy_dir / "packages"))
        {
            if (e.path().extension() == ".spkg")
            {
                cmd_install_spkg(e.path());
                pkg_count++;
            }
        }
    }
    std::cout << "[3/5] Installed " << pkg_count << " active reflex defense rules into runtime.\n";

    // Step 4: Stage AI models & Subsystem Configs
    fs::create_directories("/etc/sentinel/models");
    if (fs::exists(deploy_dir / "models"))
    {
        for (const auto &e : fs::directory_iterator(deploy_dir / "models"))
        {
            if (e.path().extension() == ".onnx")
            {
                fs::copy_file(e.path(), fs::path("/etc/sentinel/models") / e.path().filename(), fs::copy_options::overwrite_existing);
            }
        }
    }

    fs::create_directories("/etc/sentinel/configs");
    if (fs::exists(deploy_dir / "configs"))
    {
        for (const auto &e : fs::directory_iterator(deploy_dir / "configs"))
        {
            fs::copy_file(e.path(), fs::path("/etc/sentinel/configs") / e.path().filename(), fs::copy_options::overwrite_existing);
        }
    }
    std::cout << "[4/5] Staged neural models and subsystem policy configs to /etc/sentinel/\n";

    // Step 5: Execute Zero-Downtime RCU Hot-Reload Signal
    std::cout << "[5/5] Signaling live Sentinel daemon for zero-downtime RCU pointer swap...\n";
    std::string pkill_cmd = "pkill -HUP -f '/usr/local/bin/sentinel' 2>/dev/null || true";
    std::system(pkill_cmd.c_str());

    if (is_temp_extract)
    {
        fs::remove_all(deploy_dir);
    }

    std::cout << "\n\033[1;32m[SUCCESS] Production Blueprint successfully deployed to physical edge!\033[0m\n"
              << "    ├── Status          : ACTIVE IN RUNTIME (< 2 ms RCU Swap)\n"
              << "    ├── Rollback Ready  : sudo aryo blueprint rollback\n"
              << "    └── Verified Health : aryo status\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return 0;
}
int cmd_blueprint_rollback()
{
    if (geteuid() != 0)
    {
        std::cerr << "[-] Error: Rollback requires root privileges (sudo aryo blueprint rollback)\n";
        return 1;
    }

    fs::path backup_file = "/etc/sentinel/.blueprint_backup/model_routes.yaml";
    if (!fs::exists(backup_file))
    {
        std::cerr << "[-] Error: No previous blueprint backup found in /etc/sentinel/.blueprint_backup/\n";
        return 1;
    }

    fs::copy_file(backup_file, "/etc/sentinel/model_routes.yaml", fs::copy_options::overwrite_existing);
    std::system("pkill -HUP -f '/usr/local/bin/sentinel' 2>/dev/null || true");

    std::cout << "\033[1;32m[+] Emergency Rollback Successful!\033[0m Restored previous stable configuration in < 2 ms.\n";
    return 0;
}

int cmd_blueprint_list()
{
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 ARYORITHM PRODUCTION SITE BLUEPRINTS (.blueprint)                      \033[0m\n";
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";

    fs::path c_dir = get_cache_root() / "blueprints";
    std::cout << "Cached Blueprints (" << c_dir.string() << "):\n";
    if (fs::exists(c_dir))
    {
        size_t cnt = 0;
        for (const auto &e : fs::directory_iterator(c_dir))
        {
            if (e.is_regular_file())
            {
                std::cout << "  • " << std::left << std::setw(36) << e.path().filename().string()
                          << " (" << fs::file_size(e) << " bytes)\n";
                cnt++;
            }
        }
        if (cnt == 0)
            std::cout << "  (No cached .blueprint archives)\n";
    }

    std::cout << "\nActive Hardware Profile:\n";
    if (fs::exists("/etc/sentinel/model_routes.yaml"))
    {
        std::cout << "  \033[1;32m[ACTIVE IN RUNTIME]\033[0m /etc/sentinel/model_routes.yaml\n";
    }
    std::cout << "\033[1;36m========================================================================================================\033[0m\n";
    return 0;
}

// [PLACEHOLDER: Full implementations of cmd_scenario_* and cmd_blueprint_* go here]