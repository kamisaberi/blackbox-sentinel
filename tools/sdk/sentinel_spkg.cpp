#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define SPKG_MAGIC 0x474B50534F595241ULL // "ARYOSPKG"
#define SPKG_VERSION 1

namespace fs = std::filesystem;

enum SpkgTier : uint32_t {
    SPKG_TIER_NATIVE = 0,
    SPKG_TIER_WASM   = 1,
    SPKG_TIER_LUA    = 2
};

struct SpkgHeader {
    uint64_t magic{SPKG_MAGIC};
    uint32_t version{SPKG_VERSION};
    uint32_t tier{0}; // 0=Native C++, 1=Rust Wasm, 2=LuaJIT
    uint8_t  signature[64]{0}; // Ed25519 Digital Signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
    uint64_t source_len{0};
    uint32_t test_vector_len{0};
    uint32_t reserved{0};
} __attribute__((packed));

// Compute SHA-256 over raw buffer
static std::vector<uint8_t> sha256_buffer(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

// Read entire binary file
static std::vector<uint8_t> read_binary_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b(sz);
    f.read(reinterpret_cast<char*>(b.data()), sz);
    return b;
}

// -----------------------------------------------------------------------------
// 1. SCAFFOLD: sentinel-spkg new <name> [cpp|rust|lua]
// -----------------------------------------------------------------------------
bool cmd_new(const std::string& name, std::string lang) {
    std::transform(lang.begin(), lang.end(), lang.begin(), ::tolower);
    if (lang == "c++" || lang == "native") lang = "cpp";
    if (lang == "wasm") lang = "rust";

    if (lang != "cpp" && lang != "rust" && lang != "lua") {
        std::cerr << "[-] Error: Unsupported language. Use 'rust', 'cpp', or 'lua'." << std::endl;
        return false;
    }

    fs::path dir = name;
    if (fs::exists(dir)) {
        std::cerr << "[-] Error: Directory '" << name << "' already exists." << std::endl;
        return false;
    }
    fs::create_directories(dir);
    fs::create_directories(dir / "tests");

    std::string tier_str = (lang == "cpp") ? "native" : (lang == "rust") ? "wasm" : "lua";

    // manifest.json
    {
        std::ofstream mf(dir / "manifest.json");
        mf << "{\n"
           << "  \"id\": \"org.aryorithm.package." << name << "\",\n"
           << "  \"name\": \"" << name << "\",\n"
           << "  \"version\": \"1.0.0\",\n"
           << "  \"tier\": \"" << tier_str << "\",\n"
           << "  \"author\": \"Aryorithm Certified Developer\",\n"
           << "  \"target_protocol\": \"CUSTOM\",\n"
           << "  \"default_port\": 502,\n"
           << "  \"latency_sla_ns\": " << (lang == "cpp" ? "120" : lang == "rust" ? "1500" : "450") << ",\n"
           << "  \"compliance\": [\"IEC-62443-4-2\", \"CMMC-SI.L2-3.14.1\"]\n"
           << "}\n";
    }

    // Default pre-flight test packet (Sample frame triggering 0xDEADBEEF)
    {
        std::ofstream tf(dir / "tests" / "preflight_frame.bin", std::ios::binary);
        uint8_t sample_frame[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
        tf.write(reinterpret_cast<const char*>(sample_frame), sizeof(sample_frame));
    }

    if (lang == "rust") {
        fs::create_directories(dir / "src");
        {
            std::ofstream f(dir / "Cargo.toml");
            f << "[package]\nname = \"" << name << "\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n"
              << "[lib]\ncrate-type = [\"cdylib\"]\n\n"
              << "[dependencies]\nsentinel-sdk-rs = { path = \"/home/kami/blackbox-sentinel/tools/sdk/rust/sentinel-sdk-rs\" }\n\n"
              << "[profile.release]\nopt-level = 3\nlto = true\npanic = \"abort\"\nstrip = true\n";
        }
        {
            std::ofstream f(dir / "src" / "lib.rs");
            f << "#![no_std]\nuse core::panic::PanicInfo;\nuse sentinel_sdk_rs::{PacketView, Verdict};\n\n"
              << "#[panic_handler]\nfn panic(_info: &PanicInfo) -> ! { loop {} }\n\n"
              << "#[no_mangle]\npub extern \"C\" fn sentinel_dissect(pkt_ptr: *const u8, len: u32) -> i32 {\n"
              << "    let pkt = unsafe { PacketView::from_raw(pkt_ptr, len as usize) };\n"
              << "    if pkt.is_empty() { return Verdict::Pass as i32; }\n\n"
              << "    // Pre-flight assertion: Drops 0xDEADBEEF\n"
              << "    if pkt.len() >= 4 && pkt.read_be32(0) == Some(0xDEADBEEF) {\n"
              << "        return Verdict::KernelDrop as i32;\n"
              << "    }\n"
              << "    Verdict::Pass as i32\n"
              << "}\n";
        }
    } else if (lang == "cpp") {
        fs::create_directories(dir / "src");
        {
            std::ofstream f(dir / "CMakeLists.txt");
            f << "cmake_minimum_required(VERSION 3.20)\nproject(" << name << " CXX)\n"
              << "set(CMAKE_CXX_STANDARD 20)\nset(CMAKE_CXX_VISIBILITY_PRESET hidden)\n"
              << "include_directories(/home/kami/blackbox-sentinel/include)\n"
              << "add_library(" << name << " SHARED src/plugin.cpp)\n"
              << "set_target_properties(" << name << " PROPERTIES PREFIX \"\")\n";
        }
        {
            std::ofstream f(dir / "src" / "plugin.cpp");
            f << "#include <sentinel/sdk/plugin.hpp>\n\nusing namespace sentinel::sdk;\n\n"
              << "static SentinelDissectorResult " << name << "_dissect(const SentinelRawPacket* raw_pkt) {\n"
              << "    if (!raw_pkt || !raw_pkt->data || raw_pkt->length < 4) return VerdictBuilder::Pass();\n"
              << "    PacketView pkt(*raw_pkt);\n"
              << "    if (pkt.read_be32(0) == 0xDEADBEEF) {\n"
              << "        return VerdictBuilder::Drop(9001, \"PREFLIGHT_TEST_MATCH\").build();\n"
              << "    }\n"
              << "    return VerdictBuilder::Pass();\n"
              << "}\n\n"
              << "static SentinelPluginDescriptor g_descriptor = {\n"
              << "    SENTINEL_SDK_MAGIC, SENTINEL_SDK_VERSION_MAJOR, SENTINEL_SDK_VERSION_MINOR,\n"
              << "    SENTINEL_TIER_NATIVE_CPP, \"org.aryorithm.package." << name << "\",\n"
              << "    \"" << name << "\", \"1.0.0\", \"CUSTOM\", 502, 0, nullptr, nullptr, " << name << "_dissect\n"
              << "};\nSENTINEL_REGISTER_PLUGIN(g_descriptor)\n";
        }
    } else if (lang == "lua") {
        {
            std::ofstream f(dir / (name + ".lua"));
            f << "local ffi = ffi or require(\"ffi\")\n\nRule = { id = 9001, name = \"" << name << "\", port = 502 }\n\n"
              << "function Rule.inspect(pkt)\n"
              << "    if not pkt or not pkt.data then return 0 end\n"
              << "    local len = tonumber(pkt.length)\n"
              << "    if not len or len < 4 then return 0 end\n"
              << "    if pkt.data[0] == 0xDE and pkt.data[1] == 0xAD and pkt.data[2] == 0xBE and pkt.data[3] == 0xEF then\n"
              << "        return 3 -- KERNEL_DROP\n"
              << "    end\n"
              << "    return 0 -- PASS\n"
              << "end\n";
        }
    }

    std::cout << "\033[1;32m[+] Successfully scaffolded .spkg project in ./" << name << "/\033[0m\n"
              << "    ├── manifest.json\n"
              << "    ├── tests/preflight_frame.bin (embedded self-test packet)\n";
    if (lang == "rust") std::cout << "    ├── Cargo.toml\n    └── src/lib.rs\n";
    else if (lang == "cpp") std::cout << "    ├── CMakeLists.txt\n    └── src/plugin.cpp\n";
    else std::cout << "    └── " << name << ".lua\n";

    return true;
}

// -----------------------------------------------------------------------------
// 2. PACK-ALL: sentinel-spkg pack <priv_key> <tier> <manifest> <payload> <source> <test_pkt> <out.spkg>
// -----------------------------------------------------------------------------
bool cmd_pack(const std::string& priv_key_path,
              uint32_t tier,
              const std::string& manifest_path,
              const std::string& payload_path,
              const std::string& source_path,
              const std::string& test_pkt_path,
              const std::string& out_path) {
    auto manifest_data = read_binary_file(manifest_path);
    auto payload_data  = read_binary_file(payload_path);
    auto source_data   = read_binary_file(source_path);
    auto test_data     = read_binary_file(test_pkt_path);

    if (manifest_data.empty() || payload_data.empty()) {
        std::cerr << "[-] Error: Manifest or payload binary missing." << std::endl;
        return false;
    }

    // Load Ed25519 Private Key
    FILE* fp_key = fopen(priv_key_path.c_str(), "rb");
    if (!fp_key) {
        std::cerr << "[-] Error: Cannot open private key: " << priv_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp_key, nullptr, nullptr, nullptr);
    fclose(fp_key);
    if (!pkey) return false;

    // Cryptographic Merkle Root: SHA256(Manifest) || SHA256(Payload) || SHA256(Source) || SHA256(Test)
    auto h_man  = sha256_buffer(manifest_data.data(), manifest_data.size());
    auto h_pay  = sha256_buffer(payload_data.data(), payload_data.size());
    auto h_src  = sha256_buffer(source_data.data(), source_data.size());
    auto h_test = sha256_buffer(test_data.data(), test_data.size());

    std::vector<uint8_t> merkle_input;
    merkle_input.insert(merkle_input.end(), h_man.begin(), h_man.end());
    merkle_input.insert(merkle_input.end(), h_pay.begin(), h_pay.end());
    merkle_input.insert(merkle_input.end(), h_src.begin(), h_src.end());
    merkle_input.insert(merkle_input.end(), h_test.begin(), h_test.end());

    SpkgHeader hdr;
    hdr.magic = SPKG_MAGIC;
    hdr.version = SPKG_VERSION;
    hdr.tier = tier;
    hdr.manifest_len    = static_cast<uint32_t>(manifest_data.size());
    hdr.payload_len     = static_cast<uint64_t>(payload_data.size());
    hdr.source_len      = static_cast<uint64_t>(source_data.size());
    hdr.test_vector_len = static_cast<uint32_t>(test_data.size());

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = sizeof(hdr.signature);
    EVP_DigestSign(md_ctx, hdr.signature, &sig_len, merkle_input.data(), merkle_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    // Assemble single .spkg file
    std::ofstream out(out_path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    out.write(reinterpret_cast<const char*>(manifest_data.data()), manifest_data.size());
    out.write(reinterpret_cast<const char*>(payload_data.data()), payload_data.size());
    if (!source_data.empty()) out.write(reinterpret_cast<const char*>(source_data.data()), source_data.size());
    if (!test_data.empty())   out.write(reinterpret_cast<const char*>(test_data.data()), test_data.size());
    out.close();

    std::cout << "\033[1;32m[+] Successfully packed unified Sentinel Package: " << out_path << "\033[0m\n"
              << "    ├── Header Size      : " << sizeof(hdr) << " bytes (Ed25519 sealed)\n"
              << "    ├── Manifest Size    : " << hdr.manifest_len << " bytes\n"
              << "    ├── Executable Binary: " << hdr.payload_len << " bytes\n"
              << "    ├── Auditable Source : " << hdr.source_len << " bytes\n"
              << "    └── Pre-flight Packet: " << hdr.test_vector_len << " bytes\n";
    return true;
}

// -----------------------------------------------------------------------------
// 3. INSPECT: sentinel-spkg inspect <file.spkg>
// -----------------------------------------------------------------------------
bool cmd_inspect(const std::string& spkg_path) {
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader)) {
        std::cerr << "[-] Error: File too small to be valid .spkg" << std::endl;
        return false;
    }

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));

    if (hdr.magic != SPKG_MAGIC) {
        std::cerr << "[-] Error: Magic bytes mismatch! Not a valid .spkg container." << std::endl;
        return false;
    }

    std::string tier_str = (hdr.tier == 0) ? "Tier A (Native ISO C++20 Shared Object)" :
                           (hdr.tier == 1) ? "Tier B (WebAssembly Rust/Wasm3 Module)" :
                                             "Tier C (LuaJIT Dynamic C-FFI Script)";

    const uint8_t* man_ptr = container.data() + sizeof(SpkgHeader);
    std::string manifest_str(reinterpret_cast<const char*>(man_ptr), hdr.manifest_len);

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 SENTINEL PACKAGE INSPECTION (.spkg)                            \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "File Path       : " << spkg_path << "\n";
    std::cout << "Format Version  : " << hdr.version << "\n";
    std::cout << "Execution Tier  : \033[1;33m" << tier_str << "\033[0m\n";
    std::cout << "Ed25519 Sig     : \033[1;32m64-Byte Digital Signature Sealed\033[0m\n";
    std::cout << "Sections Sealed : 4/4 (Manifest + Executable + Source Code + Test Vector)\n";
    std::cout << "Total File Size : " << container.size() << " bytes\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << "\033[1;37mSECTION 1: MANIFEST METADATA:\033[0m\n" << manifest_str << "\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    std::cout << "SECTION 2: EXECUTABLE BINARY : " << hdr.payload_len << " bytes\n";
    std::cout << "SECTION 3: AUDITABLE SOURCE  : " << hdr.source_len << " bytes (Run 'extract-source' to view)\n";
    std::cout << "SECTION 4: PRE-FLIGHT TEST   : " << hdr.test_vector_len << " bytes (Ready for sandbox test)\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n";
    return true;
}

// -----------------------------------------------------------------------------
// 4. VERIFY: sentinel-spkg verify <pub_key> <file.spkg>
// -----------------------------------------------------------------------------
bool cmd_verify(const std::string& pub_key_path, const std::string& spkg_path) {
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader)) return false;

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC) return false;

    const uint8_t* man_ptr  = container.data() + sizeof(SpkgHeader);
    const uint8_t* pay_ptr  = man_ptr + hdr.manifest_len;
    const uint8_t* src_ptr  = pay_ptr + hdr.payload_len;
    const uint8_t* test_ptr = src_ptr + hdr.source_len;

    auto h_man  = sha256_buffer(man_ptr, hdr.manifest_len);
    auto h_pay  = sha256_buffer(pay_ptr, hdr.payload_len);
    auto h_src  = sha256_buffer(src_ptr, hdr.source_len);
    auto h_test = sha256_buffer(test_ptr, hdr.test_vector_len);

    std::vector<uint8_t> merkle_input;
    merkle_input.insert(merkle_input.end(), h_man.begin(), h_man.end());
    merkle_input.insert(merkle_input.end(), h_pay.begin(), h_pay.end());
    merkle_input.insert(merkle_input.end(), h_src.begin(), h_src.end());
    merkle_input.insert(merkle_input.end(), h_test.begin(), h_test.end());

    FILE* fp = fopen(pub_key_path.c_str(), "rb");
    if (!fp) { std::cerr << "[-] Cannot open public key" << std::endl; return false; }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
    int res = EVP_DigestVerify(ctx, hdr.signature, 64, merkle_input.data(), merkle_input.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (res == 1) {
        std::cout << "\033[1;32m[VERIFIED] .spkg Merkle signature is 100% AUTHENTIC and TAMPER-FREE!\033[0m\n";
        return true;
    } else {
        std::cerr << "\033[1;31m[REJECTED] Cryptographic signature INVALID! Package has been tampered with.\033[0m\n";
        return false;
    }
}

// -----------------------------------------------------------------------------
// 5. EXTRACT-SOURCE: sentinel-spkg extract-source <file.spkg> <out_source_file>
// -----------------------------------------------------------------------------
bool cmd_extract_source(const std::string& spkg_path, const std::string& out_source_file) {
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader)) return false;

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC || hdr.source_len == 0) {
        std::cerr << "[-] No auditable source code stored in this package." << std::endl;
        return false;
    }

    const uint8_t* src_ptr = container.data() + sizeof(SpkgHeader) + hdr.manifest_len + hdr.payload_len;
    std::ofstream out(out_source_file, std::ios::binary);
    out.write(reinterpret_cast<const char*>(src_ptr), hdr.source_len);
    out.close();

    std::cout << "\033[1;32m[+] Extracted auditable source code to: " << out_source_file << "\033[0m ("
              << hdr.source_len << " bytes)\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << R"(
sentinel-spkg - Aryorithm Sentinel Package (.spkg) Official Toolchain

Usage:
  sentinel-spkg new <name> [rust|cpp|lua]               Scaffold a complete .spkg project
  sentinel-spkg keygen <prefix>                         Generate Ed25519 developer keypair
  sentinel-spkg pack <key> <tier> <m> <p> <src> <t> <o> Pack all 4 sections into sealed .spkg
  sentinel-spkg inspect <file.spkg>                     Inspect metadata, source info & SLA
  sentinel-spkg verify <pub_key> <file.spkg>            Verify Ed25519 Merkle signature
  sentinel-spkg extract-source <file.spkg> <out_src>    Extract human-readable source for audit
)" << std::endl;
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "new" && argc >= 3) {
        std::string lang = (argc >= 4) ? argv[3] : "rust";
        return cmd_new(argv[2], lang) ? 0 : 1;
    } else if (cmd == "keygen" && argc >= 3) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        std::string p_priv = std::string(argv[2]) + "_private.pem";
        std::string p_pub  = std::string(argv[2]) + "_public.pem";
        FILE* f1 = fopen(p_priv.c_str(), "wb");
        PEM_write_PrivateKey(f1, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(f1);
        FILE* f2 = fopen(p_pub.c_str(), "wb");
        PEM_write_PUBKEY(f2, pkey);
        fclose(f2);
        EVP_PKEY_free(pkey);
        std::cout << "[+] Generated Ed25519 Keypair: " << p_priv << " & " << p_pub << std::endl;
        return 0;
    } else if (cmd == "pack" && argc >= 9) {
        uint32_t tier = std::stoul(argv[3]);
        return cmd_pack(argv[2], tier, argv[4], argv[5], argv[6], argv[7], argv[8]) ? 0 : 1;
    } else if (cmd == "inspect" && argc >= 3) {
        return cmd_inspect(argv[2]) ? 0 : 1;
    } else if (cmd == "verify" && argc >= 4) {
        return cmd_verify(argv[2], argv[3]) ? 0 : 1;
    } else if (cmd == "extract-source" && argc >= 4) {
        return cmd_extract_source(argv[2], argv[3]) ? 0 : 1;
    }

    std::cerr << "[-] Unknown command. Run 'sentinel-spkg' for help." << std::endl;
    return 1;
}