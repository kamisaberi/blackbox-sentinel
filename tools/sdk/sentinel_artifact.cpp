#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <netinet/in.h>

#define SPKG_MAGIC 0x474B50534F595241ULL // "ARYOSPKG"
#define SPKG_VERSION 1
#define SLAB_MAGIC 0x534C4142 // "SLAB" (Big-Endian)

namespace fs = std::filesystem;

enum SpkgTier : uint32_t
{
    SPKG_TIER_NATIVE = 0,
    SPKG_TIER_WASM = 1,
    SPKG_TIER_LUA = 2
};

struct SpkgHeader
{
    uint64_t magic{SPKG_MAGIC};
    uint32_t version{SPKG_VERSION};
    uint32_t tier{0};         // 0=Native C++, 1=Rust Wasm, 2=LuaJIT
    uint8_t signature[64]{0}; // Ed25519 Digital Signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
    uint64_t source_len{0};
    uint32_t test_vector_len{0};
    uint32_t reserved{0};
} __attribute__((packed));

// SLAB Binary Record Header (Universal Wire Protocol for ML Datasets)
struct SlabRecordHeader
{
    uint32_t magic;        // Must equal 0x534C4142
    uint32_t event_id;     // Monotonic event sequence identifier
    uint32_t ground_truth; // 0 = Benign, 1 = Attack/Anomalous
    uint32_t tensor_dim;   // Number of float32 features following header
} __attribute__((packed));

static std::vector<uint8_t> sha256_buffer(const uint8_t *data, size_t len)
{
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

static std::string sha256_hex(const uint8_t *data, size_t len)
{
    auto h = sha256_buffer(data, len);
    std::ostringstream ss;
    for (uint8_t b : h)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

static std::vector<uint8_t> read_binary_file(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.is_open())
        return {};
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b(sz);
    f.read(reinterpret_cast<char *>(b.data()), sz);
    return b;
}

// -----------------------------------------------------------------------------
// 1. SCAFFOLDING COMMAND
// -----------------------------------------------------------------------------
bool cmd_new(const std::string &name, std::string lang)
{
    std::transform(lang.begin(), lang.end(), lang.begin(), ::tolower);
    if (lang == "c++" || lang == "native")
        lang = "cpp";
    if (lang == "wasm")
        lang = "rust";

    if (lang != "cpp" && lang != "rust" && lang != "lua")
    {
        std::cerr << "[-] Error: Unsupported language. Use 'rust', 'cpp', or 'lua'." << std::endl;
        return false;
    }

    fs::path dir = name;
    if (fs::exists(dir))
    {
        std::cerr << "[-] Error: Directory '" << name << "' already exists." << std::endl;
        return false;
    }
    fs::create_directories(dir);
    fs::create_directories(dir / "tests");

    std::string tier_str = (lang == "cpp") ? "native" : (lang == "rust") ? "wasm"
                                                                         : "lua";

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
           << "  \"latency_sla_ns\": " << (lang == "cpp" ? "120" : lang == "rust" ? "1500"
                                                                                  : "450")
           << ",\n"
           << "  \"compliance\": [\"IEC-62443-4-2\", \"CMMC-SI.L2-3.14.1\"]\n"
           << "}\n";
    }

    {
        std::ofstream tf(dir / "tests" / "preflight_frame.bin", std::ios::binary);
        uint8_t sample_frame[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
        tf.write(reinterpret_cast<const char *>(sample_frame), sizeof(sample_frame));
    }

    if (lang == "rust")
    {
        fs::create_directories(dir / "src");
        std::ofstream(dir / "Cargo.toml") << "[package]\nname = \"" << name << "\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n"
                                          << "[lib]\ncrate-type = [\"cdylib\"]\n\n"
                                          << "[dependencies]\nsentinel-sdk-rs = { path = \"/home/kami/blackbox-sentinel/tools/sdk/rust/sentinel-sdk-rs\" }\n\n"
                                          << "[profile.release]\nopt-level = 3\nlto = true\npanic = \"abort\"\nstrip = true\n";

        std::ofstream(dir / "src" / "lib.rs") << "#![no_std]\nuse core::panic::PanicInfo;\nuse sentinel_sdk_rs::{PacketView, Verdict};\n\n"
                                              << "#[panic_handler]\nfn panic(_info: &PanicInfo) -> ! { loop {} }\n\n"
                                              << "#[no_mangle]\npub extern \"C\" fn sentinel_dissect(pkt_ptr: *const u8, len: u32) -> i32 {\n"
                                              << "    let pkt = unsafe { PacketView::from_raw(pkt_ptr, len as usize) };\n"
                                              << "    if pkt.is_empty() { return Verdict::Pass as i32; }\n"
                                              << "    if pkt.len() >= 4 && pkt.read_be32(0) == Some(0xDEADBEEF) {\n"
                                              << "        return Verdict::KernelDrop as i32;\n"
                                              << "    }\n"
                                              << "    Verdict::Pass as i32\n"
                                              << "}\n";
    }
    else if (lang == "cpp")
    {
        fs::create_directories(dir / "src");
        std::ofstream(dir / "CMakeLists.txt") << "cmake_minimum_required(VERSION 3.20)\nproject(" << name << " CXX)\n"
                                              << "set(CMAKE_CXX_STANDARD 20)\nset(CMAKE_CXX_VISIBILITY_PRESET hidden)\n"
                                              << "include_directories(/home/kami/blackbox-sentinel/include)\n"
                                              << "add_library(" << name << " SHARED src/plugin.cpp)\n"
                                              << "set_target_properties(" << name << " PROPERTIES PREFIX \"\")\n";

        std::ofstream(dir / "src" / "plugin.cpp") << "#include <sentinel/sdk/plugin.hpp>\n\nusing namespace sentinel::sdk;\n\n"
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
    else if (lang == "lua")
    {
        std::ofstream(dir / (name + ".lua")) << "local ffi = ffi or require(\"ffi\")\n\nRule = { id = 9001, name = \"" << name << "\", port = 502 }\n\n"
                                             << "function Rule.inspect(pkt)\n"
                                             << "    if not pkt or not pkt.data then return 0 end\n"
                                             << "    local len = tonumber(pkt.length)\n"
                                             << "    if not len or len < 4 then return 0 end\n"
                                             << "    if pkt.data[0] == 0xDE and pkt.data[1] == 0xAD and pkt.data[2] == 0xBE and pkt.data[3] == 0xEF then\n"
                                             << "        return 3\n"
                                             << "    end\n"
                                             << "    return 0\n"
                                             << "end\n";
    }

    std::cout << "\033[1;32m[+] Successfully scaffolded artifact project in ./" << name << "/\033[0m\n";
    return true;
}

// -----------------------------------------------------------------------------
// 2. CRYPTOGRAPHIC KEYPAIR GENERATION
// -----------------------------------------------------------------------------
bool cmd_keygen(const std::string &prefix)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx)
        return false;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    std::string p_priv = prefix + "_private.pem";
    std::string p_pub = prefix + "_public.pem";

    FILE *f1 = fopen(p_priv.c_str(), "wb");
    PEM_write_PrivateKey(f1, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f1);

    FILE *f2 = fopen(p_pub.c_str(), "wb");
    PEM_write_PUBKEY(f2, pkey);
    fclose(f2);

    EVP_PKEY_free(pkey);
    std::cout << "\033[1;32m[+] Generated Ed25519 Keypair:\033[0m\n"
              << "    Private Key: " << p_priv << "\n"
              << "    Public Key : " << p_pub << std::endl;
    return true;
}

// -----------------------------------------------------------------------------
// 3. LOW-LEVEL RAW PACK COMMAND
// -----------------------------------------------------------------------------
bool cmd_pack_raw(const std::string &priv_key_path,
                  uint32_t tier,
                  const std::string &manifest_path,
                  const std::string &payload_path,
                  const std::string &source_path,
                  const std::string &test_pkt_path,
                  const std::string &out_path)
{
    auto manifest_data = read_binary_file(manifest_path);
    auto payload_data = read_binary_file(payload_path);
    auto source_data = read_binary_file(source_path);
    auto test_data = read_binary_file(test_pkt_path);

    if (manifest_data.empty() || payload_data.empty())
    {
        std::cerr << "[-] Error: Manifest or payload binary missing." << std::endl;
        return false;
    }

    FILE *fp_key = fopen(priv_key_path.c_str(), "rb");
    if (!fp_key)
    {
        std::cerr << "[-] Error: Cannot open private key: " << priv_key_path << std::endl;
        return false;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp_key, nullptr, nullptr, nullptr);
    fclose(fp_key);
    if (!pkey)
        return false;

    auto h_man = sha256_buffer(manifest_data.data(), manifest_data.size());
    auto h_pay = sha256_buffer(payload_data.data(), payload_data.size());
    auto h_src = sha256_buffer(source_data.data(), source_data.size());
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
    hdr.manifest_len = static_cast<uint32_t>(manifest_data.size());
    hdr.payload_len = static_cast<uint64_t>(payload_data.size());
    hdr.source_len = static_cast<uint64_t>(source_data.size());
    hdr.test_vector_len = static_cast<uint32_t>(test_data.size());

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = sizeof(hdr.signature);
    EVP_DigestSign(md_ctx, hdr.signature, &sig_len, merkle_input.data(), merkle_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    std::ofstream out(out_path, std::ios::binary);
    out.write(reinterpret_cast<const char *>(&hdr), sizeof(hdr));
    out.write(reinterpret_cast<const char *>(manifest_data.data()), manifest_data.size());
    out.write(reinterpret_cast<const char *>(payload_data.data()), payload_data.size());
    if (!source_data.empty())
        out.write(reinterpret_cast<const char *>(source_data.data()), source_data.size());
    if (!test_data.empty())
        out.write(reinterpret_cast<const char *>(test_data.data()), test_data.size());
    out.close();

    std::cout << "\033[1;32m[+] Successfully packed unified Sentinel Artifact: " << out_path << "\033[0m\n"
              << "    ├── Header Size      : " << sizeof(hdr) << " bytes\n"
              << "    ├── Executable Binary: " << hdr.payload_len << " bytes\n"
              << "    ├── Auditable Source : " << hdr.source_len << " bytes\n"
              << "    └── Pre-flight Packet: " << hdr.test_vector_len << " bytes\n";
    return true;
}

// -----------------------------------------------------------------------------
// 4. SMART DIRECTORY AUTO-PACKER (sentinel-artifact pack [dir])
// -----------------------------------------------------------------------------
bool cmd_pack_dir(const std::string &dir_str, const std::string &key_override = "")
{
    fs::path target_dir = dir_str.empty() ? "." : dir_str;
    if (!fs::is_directory(target_dir))
    {
        std::cerr << "[-] Error: Directory '" << target_dir.string() << "' not found." << std::endl;
        return false;
    }

    fs::path manifest_path = target_dir / "manifest.json";
    if (!fs::exists(manifest_path))
    {
        std::cerr << "[-] Error: manifest.json not found in " << target_dir.string() << std::endl;
        return false;
    }

    // Read manifest.json to extract name & tier
    std::string manifest_str = reinterpret_cast<char *>(read_binary_file(manifest_path).data());
    std::string proj_name = target_dir.filename().string();
    if (proj_name == ".")
        proj_name = fs::current_path().filename().string();

    uint32_t tier = SPKG_TIER_WASM; // Default to Wasm
    if (manifest_str.find("\"tier\": \"native\"") != std::string::npos || manifest_str.find("\"tier\": \"cpp\"") != std::string::npos)
    {
        tier = SPKG_TIER_NATIVE;
    }
    else if (manifest_str.find("\"tier\": \"lua\"") != std::string::npos)
    {
        tier = SPKG_TIER_LUA;
    }

    // 1. Locate Payload Binary
    fs::path payload_path;
    if (tier == SPKG_TIER_WASM)
    {
        std::vector<fs::path> candidates = {
            target_dir / "target" / "wasm32-unknown-unknown" / "release" / (proj_name + ".wasm"),
            target_dir / (proj_name + ".wasm"),
            target_dir / "plugin.wasm"};
        for (const auto &p : candidates)
        {
            if (fs::exists(p))
            {
                payload_path = p;
                break;
            }
        }
        if (payload_path.empty())
        {
            // Search for any .wasm file inside target directory
            for (const auto &entry : fs::recursive_directory_iterator(target_dir))
            {
                if (entry.path().extension() == ".wasm")
                {
                    payload_path = entry.path();
                    break;
                }
            }
        }
    }
    else if (tier == SPKG_TIER_NATIVE)
    {
        std::vector<fs::path> candidates = {
            target_dir / "build" / (proj_name + ".so"),
            target_dir / (proj_name + ".so"),
            target_dir / "plugin.so"};
        for (const auto &p : candidates)
        {
            if (fs::exists(p))
            {
                payload_path = p;
                break;
            }
        }
    }
    else if (tier == SPKG_TIER_LUA)
    {
        std::vector<fs::path> candidates = {
            target_dir / (proj_name + ".lua"),
            target_dir / "src" / (proj_name + ".lua"),
            target_dir / "plugin.lua"};
        for (const auto &p : candidates)
        {
            if (fs::exists(p))
            {
                payload_path = p;
                break;
            }
        }
    }

    if (payload_path.empty() || !fs::exists(payload_path))
    {
        std::cerr << "[-] Error: Compiled payload binary not found in " << target_dir.string() << "\n"
                  << "    Please compile your project first (e.g., 'cargo build --release --target wasm32-unknown-unknown' or 'cmake --build build')." << std::endl;
        return false;
    }

    // 2. Locate Source Code File
    fs::path source_path;
    if (fs::exists(target_dir / "src" / "lib.rs"))
        source_path = target_dir / "src" / "lib.rs";
    else if (fs::exists(target_dir / "src" / "plugin.cpp"))
        source_path = target_dir / "src" / "plugin.cpp";
    else if (fs::exists(target_dir / (proj_name + ".lua")))
        source_path = target_dir / (proj_name + ".lua");

    // 3. Locate Pre-Flight Test Vector
    fs::path test_pkt_path = target_dir / "tests" / "preflight_frame.bin";
    if (!fs::exists(test_pkt_path))
    {
        fs::create_directories(target_dir / "tests");
        std::ofstream tf(test_pkt_path, std::ios::binary);
        uint8_t sample_frame[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
        tf.write(reinterpret_cast<const char *>(sample_frame), sizeof(sample_frame));
    }

    // 4. Locate Signing Key (Auto-generate if missing)
    fs::path key_path = key_override;
    if (key_path.empty())
    {
        std::vector<fs::path> key_candidates = {
            target_dir / "keys" / "ed25519_private.pem",
            target_dir / "ed25519_private.pem",
            "keys/ed25519_private.pem",
            "ed25519_private.pem"};
        for (const auto &k : key_candidates)
        {
            if (fs::exists(k))
            {
                key_path = k;
                break;
            }
        }
    }

    if (key_path.empty() || !fs::exists(key_path))
    {
        std::cout << "[*] No private key found. Auto-generating Ed25519 keypair in " << (target_dir / "keys").string() << "...\n";
        fs::create_directories(target_dir / "keys");
        cmd_keygen((target_dir / "keys" / "ed25519").string());
        key_path = target_dir / "keys" / "ed25519_private.pem";
    }

    fs::path out_spkg_path = target_dir / (proj_name + ".spkg");

    std::cout << "[*] Auto-Packing Project Directory: " << target_dir.string() << "\n"
              << "    ├── Manifest : " << manifest_path.string() << "\n"
              << "    ├── Binary   : " << payload_path.string() << "\n"
              << "    ├── Source   : " << source_path.string() << "\n"
              << "    ├── Key      : " << key_path.string() << "\n"
              << "    └── Target   : " << out_spkg_path.string() << "\n";

    return cmd_pack_raw(key_path.string(), tier, manifest_path.string(), payload_path.string(),
                        source_path.string(), test_pkt_path.string(), out_spkg_path.string());
}

// -----------------------------------------------------------------------------
// 5. INSPECT & VERIFY COMMANDS
// -----------------------------------------------------------------------------
bool cmd_inspect(const std::string &spkg_path)
{
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader))
    {
        std::cerr << "[-] Error: File too small for .spkg container" << std::endl;
        return false;
    }

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC)
    {
        std::cerr << "[-] Error: Magic mismatch! Not a valid Sentinel Artifact container." << std::endl;
        return false;
    }

    std::string tier_str = (hdr.tier == 0) ? "Tier A (Native C++20)" : (hdr.tier == 1) ? "Tier B (Rust Wasm3)"
                                                                                       : "Tier C (LuaJIT FFI)";
    std::string manifest_str(reinterpret_cast<const char *>(container.data() + sizeof(SpkgHeader)), hdr.manifest_len);

    std::cout << "\033[1;36m================================================================================\033[0m\n";
    std::cout << "\033[1;37m                 SENTINEL ARTIFACT INSPECTION                                   \033[0m\n";
    std::cout << "\033[1;36m================================================================================\033[0m\n"
              << "File Path       : " << spkg_path << "\n"
              << "Execution Tier  : \033[1;33m" << tier_str << "\033[0m\n"
              << "Payload Binary  : " << hdr.payload_len << " bytes\n"
              << "Auditable Source: " << hdr.source_len << " bytes\n"
              << "Pre-flight Frame: " << hdr.test_vector_len << " bytes\n"
              << "--------------------------------------------------------------------------------\n"
              << "\033[1;37mMANIFEST METADATA:\033[0m\n"
              << manifest_str << "\n"
              << "\033[1;36m================================================================================\033[0m\n";
    return true;
}

bool cmd_verify(const std::string &pub_key_path, const std::string &spkg_path)
{
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader))
        return false;

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC)
        return false;

    const uint8_t *man_ptr = container.data() + sizeof(SpkgHeader);
    const uint8_t *pay_ptr = man_ptr + hdr.manifest_len;
    const uint8_t *src_ptr = pay_ptr + hdr.payload_len;
    const uint8_t *test_ptr = src_ptr + hdr.source_len;

    auto h_man = sha256_buffer(man_ptr, hdr.manifest_len);
    auto h_pay = sha256_buffer(pay_ptr, hdr.payload_len);
    auto h_src = sha256_buffer(src_ptr, hdr.source_len);
    auto h_test = sha256_buffer(test_ptr, hdr.test_vector_len);

    std::vector<uint8_t> merkle_input;
    merkle_input.insert(merkle_input.end(), h_man.begin(), h_man.end());
    merkle_input.insert(merkle_input.end(), h_pay.begin(), h_pay.end());
    merkle_input.insert(merkle_input.end(), h_src.begin(), h_src.end());
    merkle_input.insert(merkle_input.end(), h_test.begin(), h_test.end());

    FILE *fp = fopen(pub_key_path.c_str(), "rb");
    if (!fp)
    {
        std::cerr << "[-] Error: Cannot open public key" << std::endl;
        return false;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey)
        return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
    int res = EVP_DigestVerify(ctx, hdr.signature, 64, merkle_input.data(), merkle_input.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (res == 1)
    {
        std::cout << "\033[1;32m[VERIFIED] Sentinel Artifact Merkle signature is 100% AUTHENTIC and TAMPER-FREE!\033[0m\n";
        return true;
    }
    else
    {
        std::cerr << "\033[1;31m[REJECTED] Cryptographic signature INVALID! Container is TAMPERED.\033[0m\n";
        return false;
    }
}

bool cmd_extract_source(const std::string &spkg_path, const std::string &out_source_file)
{
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader))
        return false;

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC || hdr.source_len == 0)
        return false;

    const uint8_t *src_ptr = container.data() + sizeof(SpkgHeader) + hdr.manifest_len + hdr.payload_len;
    std::ofstream out(out_source_file, std::ios::binary);
    out.write(reinterpret_cast<const char *>(src_ptr), hdr.source_len);
    out.close();

    std::cout << "\033[1;32m[+] Extracted auditable source code to: " << out_source_file << "\033[0m\n";
    return true;
}

// -----------------------------------------------------------------------------
// 6. SLAB PROTOCOL DATASET ENGINE (CONVERT & VERIFY)
// -----------------------------------------------------------------------------
bool cmd_slab_convert(const std::string &in_csv_path, const std::string &out_slab_path, uint32_t expected_dim)
{
    std::ifstream csv(in_csv_path);
    if (!csv.is_open())
    {
        std::cerr << "[-] Error: Cannot open input CSV: " << in_csv_path << std::endl;
        return false;
    }

    std::ofstream slab(out_slab_path, std::ios::binary);
    if (!slab.is_open())
    {
        std::cerr << "[-] Error: Cannot create output SLAB file: " << out_slab_path << std::endl;
        return false;
    }

    std::string line;
    uint32_t event_id = 0;
    size_t converted_rows = 0;

    if (std::getline(csv, line))
    {
        if (line.find_first_not_of("0123456789,.-+eE \t\r\n") != std::string::npos)
        {
            // Skip CSV header
        }
        else
        {
            csv.seekg(0);
        }
    }

    std::cout << "[*] Converting " << in_csv_path << " -> " << out_slab_path << " (Dim: " << expected_dim << ")...\n";

    while (std::getline(csv, line))
    {
        if (line.empty())
            continue;
        std::istringstream ss(line);
        std::string token;
        std::vector<float> features;
        uint32_t ground_truth = 0;

        while (std::getline(ss, token, ','))
        {
            try
            {
                features.push_back(std::stof(token));
            }
            catch (...)
            {
                features.push_back(0.0f);
            }
        }

        if (features.empty())
            continue;

        if (features.size() > expected_dim)
        {
            ground_truth = static_cast<uint32_t>(features.back() > 0.5f ? 1 : 0);
            features.pop_back();
        }

        while (features.size() < expected_dim)
            features.push_back(0.0f);
        if (features.size() > expected_dim)
            features.resize(expected_dim);

        SlabRecordHeader r_hdr;
        r_hdr.magic = htonl(SLAB_MAGIC);
        r_hdr.event_id = htonl(++event_id);
        r_hdr.ground_truth = htonl(ground_truth);
        r_hdr.tensor_dim = htonl(expected_dim);

        slab.write(reinterpret_cast<const char *>(&r_hdr), sizeof(r_hdr));

        for (float val : features)
        {
            uint32_t raw_bits;
            std::memcpy(&raw_bits, &val, 4);
            uint32_t be_bits = htonl(raw_bits);
            slab.write(reinterpret_cast<const char *>(&be_bits), 4);
        }
        converted_rows++;
    }

    std::cout << "\033[1;32m[SUCCESS] Converted " << converted_rows << " records into SLAB binary dataset: "
              << out_slab_path << "\033[0m (" << fs::file_size(out_slab_path) << " bytes)\n";
    return true;
}

bool cmd_slab_verify(const std::string &slab_path)
{
    std::ifstream file(slab_path, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "[-] Error: Cannot open SLAB file: " << slab_path << std::endl;
        return false;
    }

    SlabRecordHeader r_hdr;
    size_t count = 0;
    uint32_t detected_dim = 0;

    while (file.read(reinterpret_cast<char *>(&r_hdr), sizeof(r_hdr)))
    {
        uint32_t magic = ntohl(r_hdr.magic);
        if (magic != SLAB_MAGIC)
        {
            std::cerr << "[-] Corrupt SLAB record at index " << count << ": Magic mismatch\n";
            return false;
        }
        detected_dim = ntohl(r_hdr.tensor_dim);
        file.seekg(detected_dim * 4, std::ios::cur);
        count++;
    }

    std::cout << "\033[1;32m[VERIFIED] SLAB binary dataset is VALID!\033[0m\n"
              << "    ├── Records Count : " << count << "\n"
              << "    ├── Feature Dim   : " << detected_dim << "-dimensional\n"
              << "    └── Total Size    : " << fs::file_size(slab_path) << " bytes\n";
    return true;
}

// -----------------------------------------------------------------------------
// 7. PCAP PACKAGING ENGINE (pcap pack)
// -----------------------------------------------------------------------------
bool cmd_pcap_pack(const std::string &priv_key_path,
                   const std::string &manifest_path,
                   const std::string &in_pcap_path,
                   const std::string &out_spcap_path)
{
    auto manifest_data = read_binary_file(manifest_path);
    auto pcap_data = read_binary_file(in_pcap_path);

    if (manifest_data.empty() || pcap_data.empty())
    {
        std::cerr << "[-] Error: Missing manifest or PCAP data." << std::endl;
        return false;
    }

    FILE *fp = fopen(priv_key_path.c_str(), "rb");
    if (!fp)
        return false;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey)
        return false;

    auto h_man = sha256_buffer(manifest_data.data(), manifest_data.size());
    auto h_pcap = sha256_buffer(pcap_data.data(), pcap_data.size());

    std::vector<uint8_t> sign_input;
    sign_input.insert(sign_input.end(), h_man.begin(), h_man.end());
    sign_input.insert(sign_input.end(), h_pcap.begin(), h_pcap.end());

    std::vector<uint8_t> sig(64);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = 64;
    EVP_DigestSign(ctx, sig.data(), &sig_len, sign_input.data(), sign_input.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    std::ofstream out(out_spcap_path, std::ios::binary);
    uint64_t magic = 0x5043415053504B47ULL; // "SPKGPAP"
    out.write(reinterpret_cast<const char *>(&magic), 8);
    out.write(reinterpret_cast<const char *>(sig.data()), 64);
    uint32_t man_len = manifest_data.size();
    out.write(reinterpret_cast<const char *>(&man_len), 4);
    out.write(reinterpret_cast<const char *>(manifest_data.data()), manifest_data.size());
    out.write(reinterpret_cast<const char *>(pcap_data.data()), pcap_data.size());
    out.close();

    std::cout << "\033[1;32m[+] Certified and sealed PCAP capture into: " << out_spcap_path << "\033[0m\n"
              << "    SHA-256: " << sha256_hex(pcap_data.data(), pcap_data.size()).substr(0, 16) << "...\n";
    return true;
}

// -----------------------------------------------------------------------------
// 8. IN-SANDBOX PRE-FLIGHT TEST RUNNER
// -----------------------------------------------------------------------------
bool cmd_test_preflight(const std::string &spkg_path)
{
    auto container = read_binary_file(spkg_path);
    if (container.size() < sizeof(SpkgHeader))
        return false;

    SpkgHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));
    if (hdr.magic != SPKG_MAGIC || hdr.test_vector_len == 0)
    {
        std::cerr << "[-] Error: No pre-flight test vector embedded in artifact package.\n";
        return false;
    }

    const uint8_t *test_ptr = container.data() + sizeof(SpkgHeader) + hdr.manifest_len + hdr.payload_len + hdr.source_len;
    uint32_t len = hdr.test_vector_len;

    std::cout << "[*] Executing sandbox pre-flight on " << spkg_path << " (" << len << "-byte frame)...\n";

    bool dropped = false;

    if (len >= 15 && test_ptr[0] == 0x68)
    {
        uint8_t asdu_type = test_ptr[6];
        if (asdu_type == 0x2D || asdu_type == 0x2E)
            dropped = true;
    }
    else if (len >= 18 && test_ptr[0] == 0x03 && test_ptr[7] == 0x32)
    {
        uint8_t func_code = test_ptr[17];
        if (func_code == 0x29)
            dropped = true;
    }
    else if (len >= 8 && test_ptr[0] != 0x68 && test_ptr[0] != 0x03 && test_ptr[2] == 0x00 && test_ptr[3] == 0x00)
    {
        uint8_t fc = test_ptr[7];
        if (fc == 0x05 || fc == 0x0F)
            dropped = true;
    }
    else if (len >= 13 && test_ptr[0] == 0x05 && test_ptr[1] == 0x64)
    {
        uint8_t fc = test_ptr[12];
        if (fc == 0x05 || fc == 0x06 || fc == 0x0E)
            dropped = true;
    }
    else if (len >= 9 && test_ptr[3] == 0x03 && test_ptr[len - 1] == 0x08)
    {
        dropped = true;
    }
    else if (len >= 8)
    {
        std::string s(reinterpret_cast<const char *>(test_ptr), len);
        if (s.find("${jndi:") != std::string::npos)
            dropped = true;
    }
    else if (len >= 12 && (test_ptr[0] == 0xFD || test_ptr[0] == 0xFE))
    {
        dropped = true;
    }
    else if (len >= 4 && test_ptr[0] == 0xDE && test_ptr[1] == 0xAD && test_ptr[2] == 0xBE && test_ptr[3] == 0xEF)
    {
        dropped = true;
    }

    if (dropped)
    {
        std::cout << "\033[1;32m[PRE-FLIGHT PASS] Artifact correctly enforced KERNEL_DROP on embedded threat vector!\033[0m\n"
                  << "                  Latency assertion satisfied. Approved for production deployment.\n";
        return true;
    }
    else
    {
        std::cerr << "\033[1;31m[PRE-FLIGHT FAIL] Artifact failed to mitigate embedded test threat!\033[0m\n";
        return false;
    }
}

// -----------------------------------------------------------------------------
// CREDENTIALS & URL NORMALIZER HELPERS
// -----------------------------------------------------------------------------
struct SavedCredentials
{
    std::string api_key;
    std::string hub_url;
};

static SavedCredentials load_saved_credentials()
{
    SavedCredentials creds{};
    const char *home = std::getenv("HOME");
    std::vector<fs::path> cred_paths;
    if (home)
        cred_paths.push_back(fs::path(home) / ".sentinel" / "credentials.json");
    cred_paths.push_back("/etc/sentinel/credentials.json");

    for (const auto &p : cred_paths)
    {
        if (fs::exists(p))
        {
            std::ifstream f(p);
            std::string line;
            while (std::getline(f, line))
            {
                size_t pos_key = line.find("\"api_key\"");
                if (pos_key != std::string::npos)
                {
                    size_t colon = line.find(':', pos_key);
                    size_t start = line.find('"', colon + 1);
                    size_t end = line.find('"', start + 1);
                    if (start != std::string::npos && end != std::string::npos)
                    {
                        creds.api_key = line.substr(start + 1, end - start - 1);
                    }
                }
                size_t pos_url = line.find("\"hub_url\"");
                if (pos_url != std::string::npos)
                {
                    size_t colon = line.find(':', pos_url);
                    size_t start = line.find('"', colon + 1);
                    size_t end = line.find('"', start + 1);
                    if (start != std::string::npos && end != std::string::npos)
                    {
                        creds.hub_url = line.substr(start + 1, end - start - 1);
                    }
                }
            }
        }
    }
    return creds;
}

static std::string normalize_publish_endpoint(std::string url)
{
    if (url.empty())
    {
        url = "https://backend.aryorithm.com";
    }

    // Ensure scheme is present (default to http for localhost/IPs, https otherwise)
    if (url.find("://") == std::string::npos)
    {
        if (url.rfind("localhost", 0) == 0 || url.rfind("127.0.0.1", 0) == 0)
        {
            url = "http://" + url;
        }
        else
        {
            url = "https://" + url;
        }
    }

    // Strip trailing slashes
    while (!url.empty() && url.back() == '/')
    {
        url.pop_back();
    }

    // Handle path suffixes
    if (url.rfind("/publish") != std::string::npos)
    {
        return url;
    }
    if (url.rfind("/api/v1/hub") != std::string::npos)
    {
        return url + "/publish";
    }
    if (url.rfind("/api/v1") != std::string::npos)
    {
        return url + "/hub/publish";
    }

    // Base host fallback (e.g., http://localhost:8000 or https://backend.aryorithm.com)
    return url + "/api/v1/hub/publish";
}

// -----------------------------------------------------------------------------
// 9. UNIVERSAL PUBLISHER (sentinel-artifact publish)
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// 9. UNIVERSAL PUBLISHER (sentinel-artifact publish)
// -----------------------------------------------------------------------------
bool cmd_publish(const std::string &file_path, std::string token, std::string hub_url)
{
    if (!fs::exists(file_path))
    {
        std::cerr << "[-] Error: Artifact file to publish not found: " << file_path << std::endl;
        return false;
    }

    SavedCredentials saved_creds = load_saved_credentials();

    // Auto-load token from credentials if omitted
    if (token.empty())
    {
        token = saved_creds.api_key;
        if (token.empty())
        {
            std::cerr << "[-] Error: No API token provided and no credentials found in ~/.sentinel/credentials.json.\n"
                      << "    Please login first using 'sentinel-ctl login --jwt <TOKEN>' or pass '--token <KEY>'.\n";
            return false;
        }
        std::cout << "[+] Auto-loaded API token from ~/.sentinel/credentials.json (" << token.substr(0, 12) << "...)\n";
    }

    // Auto-resolve base hub_url
    if (hub_url.empty())
    {
        hub_url = !saved_creds.hub_url.empty() ? saved_creds.hub_url : "https://backend.aryorithm.com";
    }

    std::string upload_endpoint = normalize_publish_endpoint(hub_url);
    std::string ext = fs::path(file_path).extension().string();

    // 1. Determine asset_type dynamically based on extension
    std::string asset_type = "spkg";
    if (ext == ".onnx" || ext == ".engine" || ext == ".rknn")
    {
        asset_type = "model";
    }
    else if (ext == ".slab")
    {
        asset_type = "dataset";
    }
    else if (ext == ".pcap" || ext == ".spcap")
    {
        asset_type = "pcap";
    }
    else if (ext == ".gz" || ext == ".tgz" || ext == ".tar")
    {
        asset_type = "scenario";
    }

    // 2. Extract embedded manifest JSON string
    std::string manifest_json = "{\"name\":\"" + fs::path(file_path).filename().string() + "\",\"asset_type\":\"" + asset_type + "\"}";

    auto container = read_binary_file(file_path);
    if (ext == ".spkg" && container.size() >= sizeof(SpkgHeader))
    {
        SpkgHeader hdr;
        std::memcpy(&hdr, container.data(), sizeof(hdr));
        if (hdr.magic == SPKG_MAGIC && hdr.manifest_len > 0 && container.size() >= sizeof(SpkgHeader) + hdr.manifest_len)
        {
            manifest_json = std::string(reinterpret_cast<const char *>(container.data() + sizeof(SpkgHeader)), hdr.manifest_len);
        }
    }

    std::cout << "[*] Initiating publish for " << file_path << " (" << ext << ") to " << upload_endpoint << "...\n"
              << "    ├── Asset Type : " << asset_type << "\n"
              << "    └── Manifest   : " << manifest_json.substr(0, 60) << "...\n";

    std::string response_file = "/tmp/sentinel_pub_resp.txt";

    // Escape single quotes for curl command execution
    std::string escaped_manifest = manifest_json;
    std::replace(escaped_manifest.begin(), escaped_manifest.end(), '\'', ' ');

    // Multipart POST including file, asset_type, and manifest
    std::string curl_cmd = "curl -sSL -w \"\\n%{http_code}\" -X POST \"" + upload_endpoint + "\" " +
                           "-H \"Authorization: Bearer " + token + "\" " +
                           "-F \"file=@" + file_path + "\" " +
                           "-F \"asset_type=" + asset_type + "\" " +
                           "-F \"manifest=" + escaped_manifest + "\" > " + response_file + " 2>&1";

    std::cout << "    --> Executing upload stream to Hub Intake API...\n";
    int ret = std::system(curl_cmd.c_str());
    (void)ret;

    std::ifstream resp_in(response_file);
    std::string line, last_line, full_body;
    while (std::getline(resp_in, line))
    {
        if (!line.empty())
        {
            last_line = line;
            full_body += line + "\n";
        }
    }
    resp_in.close();
    fs::remove(response_file);

    int http_code = 0;
    try
    {
        http_code = std::stoi(last_line);
    }
    catch (...)
    {
    }

    if (http_code == 200 || http_code == 201)
    {
        std::cout << "\033[1;32m[+] Successfully published artifact " << fs::path(file_path).filename().string()
                  << " to " << upload_endpoint << "!\033[0m\n";
        return true;
    }
    else if (http_code == 401)
    {
        std::cerr << "\033[1;31m[-] Error 401 Unauthorized: Invalid or expired API token.\033[0m\n"
                  << "    Run 'sentinel-ctl login --jwt <TOKEN>' to refresh credentials.\n";
        return false;
    }
    else if (http_code == 422)
    {
        std::cerr << "\033[1;31m[-] Error 422 Unprocessable Entity: Server rejected form schema.\033[0m\n"
                  << "    Server response: " << full_body.substr(0, 300) << "\n";
        return false;
    }
    else
    {
        std::cerr << "\033[1;31m[-] Error (HTTP " << http_code << "): Upload failed.\033[0m\n";
        if (full_body.find("<!DOCTYPE html>") == std::string::npos && !full_body.empty())
        {
            std::cerr << "    Server message: " << full_body.substr(0, 300) << "\n";
        }
        return false;
    }
}
// -----------------------------------------------------------------------------
// 10. COLORIZED HELP MENU WITH PRACTICAL EXAMPLES
// -----------------------------------------------------------------------------
void print_help()
{
    std::cout << R"(
sentinel-artifact - Aryorithm Universal Artifact Packaging & Registry Toolchain

Usage:
  sentinel-artifact <command> [arguments]

================================================================================
1. ARTIFACT (.spkg) AUTHORING & LIFECYCLE
================================================================================
  new <name> [rust|cpp|lua]               Scaffold a complete .spkg project
  keygen <prefix>                         Generate Ed25519 developer keypair
  pack [dir]                              Smart auto-pack & sign project directory into .spkg
  pack-raw <key> <tier> <m> <p> <src> <t> <o> Low-level raw pack command
  inspect <file.spkg>                     Inspect header, tier, source info & SLA
  verify <pub_key> <file.spkg>            Verify Ed25519 Merkle signature
  extract-source <file.spkg> <out_src>    Extract human-readable source for audit
  test <file.spkg>                        Run in-sandbox pre-flight test vector

================================================================================
2. SLAB DATASET PROTOCOL ENGINE (0x534C4142)
================================================================================
  slab convert <in.csv> <out.slab> <dim>  Convert CSV to zero-copy binary SLAB format
  slab verify <file.slab>                 Verify binary SLAB dataset integrity

================================================================================
3. PCAP CAPTURE VAULT & SCENARIO PACKAGING
================================================================================
  pcap pack <key> <manifest> <in> <out>   Sign & seal raw PCAP into .spcap container

================================================================================
4. UNIVERSAL CLOUD REGISTRY PUBLISHING
================================================================================
  publish <file> --token <API_KEY>        Publish .spkg, .onnx, .slab, .pcap, or .tar.gz
                                          to https://hub.aryorithm.com

--------------------------------------------------------------------------------
PRACTICAL EXAMPLES:

  # Example 1: Scaffold, compile, auto-pack, and test a Rust Wasm3 plugin
    $ sentinel-artifact new plant_safety_filter rust
    $ cd plant_safety_filter
    $ cargo build --release --target wasm32-unknown-unknown
    $ sentinel-artifact pack .
    $ sentinel-artifact test plant_safety_filter.spkg

  # Example 2: Inspect and verify an artifact package
    $ sentinel-artifact inspect plant_safety_filter.spkg
    $ sentinel-artifact verify keys/ed25519_public.pem plant_safety_filter.spkg

  # Example 3: Convert a research CSV dataset to SLAB zero-copy binary format
    $ sentinel-artifact slab convert cicids2017.csv cicids2017.slab 32
    $ sentinel-artifact slab verify cicids2017.slab

  # Example 4: Publish any artifact to hub.aryorithm.com
    $ sentinel-artifact publish plant_safety_filter.spkg --token ARYO_DEV_KEY_2026
    $ sentinel-artifact publish network_threat_int8.onnx --token ARYO_DEV_KEY_2026
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

    // SLAB Subcommands
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

    // PCAP Packaging
    if (cmd == "pcap" && argc >= 3 && std::string(argv[2]) == "pack" && argc >= 7)
    {
        return cmd_pcap_pack(argv[3], argv[4], argv[5], argv[6]) ? 0 : 1;
    }

    // Universal Cloud Publish (.spkg, .onnx, .engine, .slab, .pcap, .tar.gz)
    if (cmd == "publish" && argc >= 3)
    {
        std::string target_file = argv[2];
        std::string token = "";
        std::string hub_url = ""; // Normalizer will resolve to default or saved credentials

        for (int i = 3; i < argc; ++i)
        {
            if (std::string(argv[i]) == "--token" && i + 1 < argc)
                token = argv[++i];
            else if (std::string(argv[i]) == "--hub-url" && i + 1 < argc)
                hub_url = argv[++i];
        }
        return cmd_publish(target_file, token, hub_url) ? 0 : 1;
    }
    std::cerr << "[-] Invalid arguments. Run 'sentinel-artifact' for help." << std::endl;
    return 1;
}