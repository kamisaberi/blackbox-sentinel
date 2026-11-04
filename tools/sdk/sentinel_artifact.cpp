
// ==============================================================================
// ARYORITHM UNIVERSAL ARTIFACT PACKAGING & REGISTRY TOOLCHAIN (sentinel-artifact)
// ==============================================================================
#include "sentinel_artifact/common_artifact.hpp"
#include "sentinel_artifact/artifact_packaging.hpp"
#include "sentinel_artifact/artifact_protocols.hpp"
#include "sentinel_artifact/artifact_publisher.hpp"


void print_help()
{
    std::cout << R"(
sentinel-artifact - Aryorithm Universal Artifact Packaging & Registry Toolchain

Usage:
  sentinel-artifact <command> [arguments]

Artifact (.spkg) Authoring & Lifecycle:
  new <name> [rust|cpp|lua]               Scaffold a complete .spkg project
  keygen <prefix>                         Generate Ed25519 developer keypair
  pack [dir]                              Smart auto-pack & sign project directory into .spkg
  pack-raw <key> <tier> <m> <p> <src> <t> <o> Low-level raw pack command
  inspect <file.spkg>                     Inspect header, tier, source info & SLA
  verify <pub_key> <file.spkg>            Verify Ed25519 Merkle signature
  extract-source <file.spkg> <out_src>    Extract human-readable source for audit
  test <file.spkg>                        Run in-sandbox pre-flight test vector

Autonomous Honeynet & Vaccine Synthesis:
  synthesize-vaccine <exploit.json|dir> [out_dir]
                                          Synthesize, preflight-test & seal .spkg reflex rule

SLAB Dataset Protocol Engine (0x534C4142):
  slab convert <in.csv> <out.slab> <dim>  Convert CSV to zero-copy binary SLAB format
  slab verify <file.slab>                 Verify binary SLAB dataset integrity

PCAP Capture Vault & Scenario Packaging:
  pcap pack <key> <manifest> <in> <out>   Sign & seal raw PCAP into .spcap container

Universal Cloud Registry Publishing:
  publish <file> --token <API_KEY>        Publish .spkg, .onnx, .slab, .pcap, or .tar.gz
                                          to https://backend.aryorithm.com
)" << std::endl;
}
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_help();
        return 0;
    }

    std::string cmd = argv[1];

    if (cmd == "--help" || cmd == "-h" || cmd == "help")
    {
        print_help();
        return 0;
    }

    if (cmd == "new" && argc >= 3)
    {
        std::string lang = (argc >= 4) ? argv[3] : "rust";
        return cmd_new(argv[2], lang) ? 0 : 1;
    }
    else if (cmd == "keygen" && argc >= 3)
    {
        return cmd_keygen(argv[2]) ? 0 : 1;
    }
    else if (cmd == "pack")
    {
        std::string dir = (argc >= 3) ? argv[2] : ".";
        std::string key = (argc >= 4) ? argv[3] : "";
        return cmd_pack_dir(dir, key) ? 0 : 1;
    }
    else if (cmd == "pack-raw" && argc >= 9)
    {
        uint32_t tier = std::stoul(argv[3]);
        return cmd_pack_raw(argv[2], tier, argv[4], argv[5], argv[6], argv[7], argv[8]) ? 0 : 1;
    }
    else if (cmd == "inspect" && argc >= 3)
    {
        return cmd_inspect(argv[2]) ? 0 : 1;
    }
    else if (cmd == "verify" && argc >= 4)
    {
        return cmd_verify(argv[2], argv[3]) ? 0 : 1;
    }
    else if (cmd == "extract-source" && argc >= 4)
    {
        return cmd_extract_source(argv[2], argv[3]) ? 0 : 1;
    }
    else if (cmd == "test" && argc >= 3)
    {
        return cmd_test_preflight(argv[2]) ? 0 : 1;
    }

    if (cmd == "slab" && argc >= 3)
    {
        std::string sub = argv[2];
        if (sub == "convert" && argc >= 6)
        {
            uint32_t dim = std::stoul(argv[5]);
            return cmd_slab_convert(argv[3], argv[4], dim) ? 0 : 1;
        }
        else if (sub == "verify" && argc >= 4)
        {
            return cmd_slab_verify(argv[3]) ? 0 : 1;
        }
    }

    if (cmd == "pcap" && argc >= 3 && std::string(argv[2]) == "pack" && argc >= 7)
    {
        return cmd_pcap_pack(argv[3], argv[4], argv[5], argv[6]) ? 0 : 1;
    }

    if (cmd == "publish" && argc >= 3)
    {
        std::string target_file = argv[2];
        std::string token = "";
        std::string hub_url = "";

        for (int i = 3; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--token" && i + 1 < argc)
                token = argv[++i];
            else if (std::string(argv[i]) == "--hub-url" && i + 1 < argc)
                hub_url = argv[++i];
        }
        return cmd_publish(target_file, token, hub_url) ? 0 : 1;
    }
    if (cmd == "synthesize-vaccine" && argc >= 3)
    {
        std::string target = argv[2];
        std::string out_dir = (argc >= 4) ? argv[3] : "";
        return cmd_synthesize_vaccine(target, out_dir) ? 0 : 1;
    }
    std::cerr << "[-] Invalid arguments. Run 'sentinel-artifact' for help." << std::endl;
    return 1;
}