// ==============================================================================
// BLACKBOX SENTINEL APPLIANCE OPERATOR CLI (sentinel-ctl)
// ==============================================================================
#include "sentinel_ctl/common_ctl.hpp"
#include "sentinel_ctl/ctl_appliance_security.hpp"
#include "sentinel_ctl/ctl_registry_assets.hpp"
#include "sentinel_ctl/ctl_blueprints_scenarios.hpp"
#include "sentinel_ctl/ctl_cache_engine.hpp"

void print_help()
{
    std::cout << R"(
sentinel-ctl - Blackbox Sentinel Appliance & Unified Registry Asset Manager

Usage:
  sentinel-ctl <domain> <action> [arguments]

Authentication & Registry Identity:
  login --jwt <JWT_TOKEN>          Exchange JWT for live API key & save credentials
  whoami                           Display current authenticated registry identity

Global Hub Discovery (Live Cloud Catalog):
  hub search [query] [--type <t>]  Search live catalog (package, model, dataset, pcap, scenario)
  hub list [--type <type>]         List all published assets on hub.aryorithm.com
  hub info <type> <slug>           Preview cloud manifest, SLA & signature without downloading

Unified Asset Lifecycles (pack, pull, inspect, list):
  package pull <slug>              Pull verified .spkg and deploy to active runtime
  package list                     List active and cached extension packages (.spkg)
  model pull <model_slug>          Pull verified ONNX model weights into models/
  model list                       List locally cached and staged AI models
  dataset pull <slug>              Pull zero-copy .slab telemetry dataset into cache
  dataset list                     List locally cached .slab datasets
  pcap pack <file.pcap> [--category <cat>] [--protocol <p>] [--attack <type>]
                                   Pack PCAP capture & auto-generate Hub companion manifest
  pcap pull <slug>                 Pull certified malware PCAP into /etc/sentinel/pcaps/
  pcap list                        List locally cached and staged PCAP captures
  scenario pack <dir> [out.tar.gz] Pack scenario directory into verified bundle for Hub
  scenario pull <slug>             Pull certified scenario bundle and stage to sentinel-matrix
  scenario list                    List locally cached and staged digital twin scenarios
  model pack <model.onnx> [--precision INT8|FP32] [--domain <d>] 
                                   Pack ONNX model & generate compliant companion manifest
  model pull <model_slug>          Pull verified ONNX model weights into models/
  model list                       List locally cached and staged AI models

Cache Management:
  cache list                       List all cached assets and sizes
  cache search <query> [--type <t>] Search local cache by keyword and asset type
  cache clean                      Purge the local asset cache
  cache export <out.tar.gz>        Export cache to offline USB bundle
  cache import <in.tar.gz>         Import offline bundle into local cache

Appliance & Security Engines:
  status                           Inspect appliance licensing, hardware root & eBPF health
  sync <routes.yaml>               Audit dependencies & resolve missing assets from cache
  launch <routes.yaml>             Synchronize and launch Sentinel daemon in one step
  5g enable|status                 3GPP 5G/6G N3 GTP-U wireless network slicing guard
  sbom generate|enforce|status     Live-SBOM in-kernel W^X memory drift defense
  trism status|inspect|policy      AI TRiSM prompt injection firewall & tool governor

Scenario & Digital Twin Management:
  scenario new <name> [--sector <s>] Scaffolds complete turnkey scenario project
  scenario add <dir> <asset> [--embed] Add package/model/pcap by name without paths
  scenario pack <dir> [--embed]      Pack scenario (default: referenced ~15KB, --embed: standalone)
  scenario pull <slug>               Pull verified scenario from Hub & stage to sentinel-matrix
  scenario list                      List all locally cached and staged digital twin scenarios

Production Site Blueprints & Hardware Provisioning:
  blueprint new <name> [--site <s>] Scaffold physical production blueprint
  blueprint add <dir> <asset>       Add package/model dependency by name or path
  blueprint pack <dir> [--embed]    Pack blueprint into .blueprint bundle
  blueprint inspect <file|dir>      Inspect hardware NIC bindings, DAG & SLA
  blueprint deploy <file|dir>       Atomically deploy to /etc/sentinel/ (with auto-backup)
  blueprint rollback                Instantly restore previous configuration from backup
  blueprint list                    List active and cached production blueprints
)" << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_help();
        return 0;
    }

    // 1. Inherit registry URL from credentials.json first
    SavedCredentials creds = load_saved_credentials();
    if (!creds.hub_url.empty())
    {
        g_hub_url = creds.hub_url;
    }

    // 2. Allow environment variable to override credentials if explicitly set
    const char *env_url = std::getenv("SENTINEL_HUB_URL");
    if (env_url && std::strlen(env_url) > 0)
    {
        g_hub_url = env_url;
    }
    std::string cmd = argv[1];

    if (cmd == "status")
        return cmd_status();
    if (cmd == "whoami")
        return cmd_whoami();
    if (cmd == "login")
    {
        std::string jwt = "";
        std::string hub_url = g_hub_url;
        for (int i = 2; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--jwt" && i + 1 < argc)
                jwt = argv[++i];
            else if (std::string(argv[i]) == "--hub-url" && i + 1 < argc)
                hub_url = argv[++i];
            else if (jwt.empty() && argv[i][0] != '-')
                jwt = argv[i];
        }
        return cmd_login(jwt, hub_url);
    }

    // Support both: 'sentinel-ctl install <file>' AND 'sentinel-ctl appliance install <file>'
    if ((cmd == "install" && argc >= 3) || (cmd == "appliance" && argc >= 4 && std::string(argv[2]) == "install"))
    {
        std::string spkg_path = (cmd == "appliance") ? argv[3] : argv[2];
        return cmd_install_spkg(spkg_path);
    }
    if (cmd == "pcap" && argc >= 4 && std::string(argv[2]) == "pull")
        return cmd_pcap_pull(argv[3]);
    if (cmd == "dataset" && argc >= 4 && std::string(argv[2]) == "pull")
        return cmd_dataset_pull(argv[3]);

    if (cmd == "cache" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "list")
            return cmd_cache_list();
        if (sub == "clean")
            return cmd_cache_clean();
        if (sub == "export" && argc >= 4)
            return cmd_cache_export(argv[3]);
        if (sub == "import" && argc >= 4)
            return cmd_cache_import(argv[3]);
    }

    if (cmd == "slab" && argc >= 4 && std::string(argv[2]) == "stream")
    {
        uint16_t port = (argc >= 5) ? static_cast<uint16_t>(std::stoul(argv[4])) : 9999;
        return cmd_slab_stream(argv[3], port);
    }

    if (cmd == "model" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "pack" && argc >= 4)
        {
            std::string precision = "";
            std::string domain = "";
            for (int i = 4; i < argc; ++i)
            {
                if (std::string(argv[i]) == "--precision" && i + 1 < argc)
                    precision = argv[++i];
                else if (std::string(argv[i]) == "--domain" && i + 1 < argc)
                    domain = argv[++i];
            }
            return cmd_model_pack(argv[3], precision, domain);
        }
        if (sub == "pull" && argc >= 4)
            return cmd_model_pull(argv[3]);
        if (sub == "list")
            return cmd_generic_list("models", "models", ".onnx");
    }
    if (cmd == "sync" || cmd == "check" || cmd == "launch")
    {
        fs::path yaml_path = (argc >= 3) ? argv[2] : "configs/model_routes.yaml";

        if (!fs::exists(yaml_path))
        {
            if (fs::exists("../" + yaml_path.string()))
            {
                yaml_path = "../" + yaml_path.string();
            }
            else if (fs::exists("/etc/sentinel/" + yaml_path.filename().string()))
            {
                yaml_path = "/etc/sentinel/" + yaml_path.filename().string();
            }
            else
            {
                std::cerr << "[-] Error: Routing specification file not found: " << yaml_path << std::endl;
                return 1;
            }
        }

        std::cout << "\033[1;36m================================================================================\033[0m\n";
        std::cout << "\033[1;37m        SENTINEL CACHE-FIRST DEPENDENCY AUDIT: " << yaml_path.filename().string() << "\033[0m\n";
        std::cout << "\033[1;36m================================================================================\033[0m\n";

        DependencyManifest deps = parse_yaml_requirements(yaml_path);

        std::cout << "[*] Discovered Requirements from " << yaml_path.string() << ":\n"
                  << "    ├── Packages (.spkg): " << deps.required_spkgs.size() << "\n"
                  << "    └── Models (ONNX)   : " << deps.required_models.size() << "\n\n";

        std::cout << "\033[1;33m--- [1/2] RESOLVING SENTINEL PACKAGES (.spkg) ---\033[0m\n";
        size_t spkg_installed = 0;
        fs::create_directories("/etc/sentinel/plugins.d");
        fs::create_directories("/etc/sentinel/wasm.d");
        fs::create_directories("/etc/sentinel/rules.d");

        for (const auto &pkg : deps.required_spkgs)
        {
            std::string stem = package_id_to_stem(pkg);
            std::string pkg_filename = stem + ".spkg";
            fs::path cached_pkg_path;

            if (resolve_cached_asset("packages", pkg_filename, cached_pkg_path))
            {
                if (cmd == "sync" || cmd == "launch")
                {
                    cmd_install_spkg(cached_pkg_path);
                }
                spkg_installed++;
            }
        }

        std::cout << "\n\033[1;33m--- [2/2] RESOLVING NEURAL ONNX MODELS ---\033[0m\n";
        size_t models_installed = 0;
        fs::create_directories("models");

        for (const auto &mdl : deps.required_models)
        {
            std::string mdl_filename = mdl + ".onnx";
            fs::path cached_mdl_path;

            if (resolve_cached_asset("models", mdl_filename, cached_mdl_path))
            {
                if (cmd == "sync" || cmd == "launch")
                {
                    fs::copy_file(cached_mdl_path, fs::path("models") / mdl_filename, fs::copy_options::overwrite_existing);
                }
                models_installed++;
            }
        }

        std::cout << "\n\033[1;36m================================================================================\033[0m\n";
        bool all_ok = (spkg_installed == deps.required_spkgs.size() && models_installed == deps.required_models.size());

        if (all_ok)
        {
            std::cout << "\033[1;32m[SUCCESS] All packages and AI models resolved from cache! Ready to launch.\033[0m\n";
            std::cout << "Launch command: \033[1;37msudo ./build/sentinel --routes " << yaml_path.string() << "\033[0m\n";
        }
        else
        {
            std::cout << "\033[1;31m[-] Unsatisfied dependencies detected. Run: sentinel-ctl sync " << yaml_path.string() << "\033[0m\n";
            return 1;
        }
        std::cout << "\033[1;36m================================================================================\033[0m\n";

        if (cmd == "launch" && all_ok)
        {
            std::cout << "\n[*] Executing Sentinel with " << yaml_path.string() << "...\n";
            std::string exec_cmd = "sudo ./build/sentinel --routes " + yaml_path.string();
            return std::system(exec_cmd.c_str());
        }

        return 0;
    }

    if (cmd == "hardware" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "status")
            return cmd_hardware_status();
        if (sub == "enroll")
            return cmd_hardware_enroll();
    }

    // Inside main() of sentinel_ctl.cpp:
    if (cmd == "license" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "apply" && argc >= 4)
            return cmd_license_apply(argv[3]);
        if (sub == "inspect" && argc >= 4)
            return cmd_license_inspect(argv[3]);
    }

    if (cmd == "5g" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "enable")
        {
            std::string iface = (argc >= 4) ? argv[3] : "ens33";
            fs::path cfg = (argc >= 5) ? argv[4] : "configs/5g_slices.yaml";
            return cmd_5g_enable(iface, cfg);
        }
        if (sub == "status")
            return cmd_5g_status();
    }
    if (cmd == "sbom" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "generate")
            return cmd_sbom_generate();
        if (sub == "enforce")
            return cmd_sbom_enforce();
        if (sub == "status")
            return cmd_sbom_status();
        if (sub == "test-drift")
            return cmd_sbom_test_drift();
    }
    if (cmd == "trism" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "status")
            return cmd_trism_status();
        if (sub == "test-jailbreak")
            return cmd_trism_test_jailbreak();
        if (sub == "policy")
        {
            std::string act = (argc >= 4) ? argv[3] : "show";
            return cmd_trism_policy(act);
        }
        if (sub == "inspect")
        {
            std::string prompt = "";
            for (int i = 3; i < argc; ++i)
            {
                if ((std::string(argv[i]) == "--prompt" || std::string(argv[i]) == "-p") && i + 1 < argc)
                {
                    prompt = argv[++i];
                }
            }
            if (prompt.empty() && argc >= 4)
                prompt = argv[3];
            return cmd_trism_inspect(prompt);
        }
    }
    if (cmd == "scenario" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "new" || sub == "create")
        {
            std::string name = (argc >= 4) ? argv[3] : "custom_scenario";
            std::string sector = "";
            for (int i = 4; i < argc; ++i)
                if (std::string(argv[i]) == "--sector" && i + 1 < argc)
                    sector = argv[++i];
            return cmd_scenario_new(name, sector);
        }
        if (sub == "add" && argc >= 5)
        {
            bool embed = false;
            for (int i = 5; i < argc; ++i)
                if (std::string(argv[i]) == "--embed")
                    embed = true;
            return cmd_scenario_add(argv[3], argv[4], embed);
        }
        if (sub == "pack" && argc >= 4)
        {
            bool embed = false;
            std::string out_tar = "";
            for (int i = 4; i < argc; ++i)
            {
                if (std::string(argv[i]) == "--embed" || std::string(argv[i]) == "--standalone")
                    embed = true;
                else if (argv[i][0] != '-')
                    out_tar = argv[i];
            }
            return cmd_scenario_pack(argv[3], out_tar, embed);
        }
        if (sub == "pull" && argc >= 4)
            return cmd_scenario_pull(argv[3]);
        if (sub == "list")
            return cmd_scenario_list();
    }
    // -------------------------------------------------------------------------
    // HUB ONLINE DISCOVERY COMMANDS
    // -------------------------------------------------------------------------
    if (cmd == "hub" && argc >= 3)
    {
        std::string sub = argv[2];

        if (sub == "visibility" && argc >= 5)
        {
            std::string type = argv[3];
            std::string slug = argv[4];
            std::string mode = (argc >= 6) ? argv[5] : "public";
            return cmd_hub_visibility(type, slug, mode);
        }
        if (sub == "search" || sub == "list")
        {
            std::string q = (argc >= 4 && argv[3][0] != '-') ? argv[3] : "";
            std::string t = "";
            for (int i = 3; i < argc; ++i)
            {
                if (std::string(argv[i]) == "--type" && i + 1 < argc)
                    t = argv[++i];
            }
            return cmd_hub_search(q, t);
        }
        if (sub == "info" && argc >= 4)
        {
            std::string type = (argc >= 5) ? argv[3] : "package";
            std::string slug = (argc >= 5) ? argv[4] : argv[3];
            return cmd_hub_info(type, slug);
        }

        if (sub == "yank" && argc >= 5)
        {
            return cmd_hub_yank(argv[3], argv[4]);
        }
    }

    // -------------------------------------------------------------------------
    // SYMMETRICAL ASSET DOMAINS (package, model, dataset, pcap, scenario)
    // -------------------------------------------------------------------------
    if (cmd == "package" && argc >= 3)
    {
        std::string sub = argv[2];

        if (sub == "visibility" && argc >= 4)
        {
            std::string slug = argv[3];
            std::string mode = (argc >= 5) ? argv[4] : "public";
            return cmd_hub_visibility("package", slug, mode);
        }

        if (sub == "pull" && argc >= 4)
        {
            std::string pkg_name = argv[3];
            if (pkg_name.size() < 5 || pkg_name.substr(pkg_name.size() - 5) != ".spkg")
                pkg_name += ".spkg";
            fs::path staged;
            if (resolve_cached_asset("packages", pkg_name, staged))
                return cmd_install_spkg(staged);
            return 1;
        }
        if (sub == "list")
            return cmd_package_list();
    }

    if (cmd == "model" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "pull" && argc >= 4)
            return cmd_model_pull(argv[3]);
        if (sub == "list")
            return cmd_generic_list("models", "models", ".onnx");
    }

    if (cmd == "dataset" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "pull" && argc >= 4)
            return cmd_dataset_pull(argv[3]);
        if (sub == "list")
            return cmd_generic_list("datasets", "/etc/sentinel/datasets", ".slab");
    }

    if (cmd == "pcap" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "pack" && argc >= 4)
        {
            std::string cat = "";
            std::string proto = "";
            std::string attack = "";
            for (int i = 4; i < argc; ++i)
            {
                if (std::string(argv[i]) == "--category" && i + 1 < argc)
                    cat = argv[++i];
                else if (std::string(argv[i]) == "--protocol" && i + 1 < argc)
                    proto = argv[++i];
                else if (std::string(argv[i]) == "--attack" && i + 1 < argc)
                    attack = argv[++i];
            }
            return cmd_pcap_pack(argv[3], cat, proto, attack);
        }
        if (sub == "pull" && argc >= 4)
            return cmd_pcap_pull(argv[3]);
        if (sub == "list")
            return cmd_generic_list("pcaps", "/etc/sentinel/pcaps", ".pcap");
    }
    // Cache Search
    if (cmd == "cache" && argc >= 3 && std::string(argv[2]) == "search")
    {
        std::string q = (argc >= 4 && argv[3][0] != '-') ? argv[3] : "";
        std::string t = "";
        for (int i = 3; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--type" && i + 1 < argc)
                t = argv[++i];
        }
        return cmd_cache_search(q, t);
    }
    if (cmd == "blueprint" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "new")
        {
            std::string name = (argc >= 4) ? argv[3] : "site_blueprint";
            std::string site = (argc >= 6 && std::string(argv[4]) == "--site") ? argv[5] : "";
            return cmd_blueprint_new(name, site);
        }
        // Add inside main() under 'if (cmd == "blueprint")':
        if (sub == "pull" && argc >= 4)
            return cmd_blueprint_pull(argv[3]);

        // Add inside main() under 'if (cmd == "sbom")':
        if (sub == "attest")
            return cmd_sbom_attest();

        // Update inside main() under 'if (cmd == "trism")':
        if (sub == "policy")
        {
            std::string act = (argc >= 4) ? argv[3] : "show";
            return cmd_trism_policy(act);
        }
        if (sub == "add" && argc >= 5)
        {
            bool embed = (argc >= 6 && std::string(argv[5]) == "--embed");
            return cmd_blueprint_add(argv[3], argv[4], embed);
        }
        if (sub == "pack" && argc >= 4)
        {
            bool embed = false;
            std::string out_tar = "";
            for (int i = 4; i < argc; ++i)
            {
                if (std::string(argv[i]) == "--embed")
                    embed = true;
                else if (argv[i][0] != '-')
                    out_tar = argv[i];
            }
            return cmd_blueprint_pack(argv[3], out_tar, embed);
        }
        if (sub == "inspect" && argc >= 4)
            return cmd_blueprint_inspect(argv[3]);
        if (sub == "deploy" && argc >= 4)
            return cmd_blueprint_deploy(argv[3]);
        if (sub == "rollback")
            return cmd_blueprint_rollback();
        if (sub == "list")
            return cmd_blueprint_list();
    }


    // Gap 2: Hub Yank
    if (cmd == "hub" && argc >= 5 && std::string(argv[2]) == "yank")
    {
        return cmd_hub_yank(argv[3], argv[4]);
    }

    // Gap 3 & 4: Threat Vaccine Share & Feed
    if (cmd == "threat" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "vaccine-share" && argc >= 4) return cmd_threat_vaccine_share(argv[3]);
        if (sub == "vaccine-feed") return cmd_threat_vaccine_feed((argc >= 4) ? std::stoi(argv[3]) : 50);
    }

    // Gap 5: Live-SBOM Drift Events
    if (cmd == "sbom" && argc >= 3 && std::string(argv[2]) == "drift-events")
    {
int limit = 50;
        for (int i = 3; i < argc; ++i)
        {
            std::string arg = argv[i];
            if ((arg == "--limit" || arg == "-l") && i + 1 < argc)
            {
                try { limit = std::stoi(argv[++i]); } catch (...) {}
            }
            else if (arg[0] != '-')
            {
                try { limit = std::stoi(arg); } catch (...) {}
            }
        }
        return cmd_sbom_drift_events(limit);    }

    // Gap 6: TRiSM Policy Push
    if (cmd == "trism" && argc >= 4 && std::string(argv[2]) == "policy" && std::string(argv[3]) == "push")
    {
        std::string path = (argc >= 5) ? argv[4] : "configs/trism_policy.yaml";
        return cmd_trism_policy_push(path);
    }

    // Gap 7: Raw Blueprint DAG
    if (cmd == "blueprint" && argc >= 4 && std::string(argv[2]) == "raw-dag")
    {
        return cmd_blueprint_raw_dag(argv[3]);
    }

    // Gap 8: Appliance Pull
    if (cmd == "appliance" && argc >= 4 && std::string(argv[2]) == "pull")
    {
        return cmd_appliance_pull(argv[3]);
    }
    print_help();
    return 0;
}