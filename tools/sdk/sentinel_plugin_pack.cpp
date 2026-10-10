#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define SPLUGIN_MAGIC 0x314C50534F595241ULL // "ARYOSPL1"
#define SPLUGIN_VERSION 1

namespace fs = std::filesystem;

enum PluginTier : uint32_t {
    TIER_NATIVE = 0,
    TIER_WASM   = 1,
    TIER_LUA    = 2
};

struct SPluginHeader {
    uint64_t magic{SPLUGIN_MAGIC};
    uint32_t version{SPLUGIN_VERSION};
    uint32_t tier{0};
    uint8_t  signature[64]{0}; // Ed25519 signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
} __attribute__((packed));

std::vector<uint8_t> sha256_buffer(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<uint8_t> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b(sz);
    f.read(reinterpret_cast<char*>(b.data()), sz);
    return b;
}

// -----------------------------------------------------------------------------
// 1. SCAFFOLDING COMMAND: sentinel-plugin-pack new <name> [cpp|rust|lua]
// -----------------------------------------------------------------------------
bool cmd_new(const std::string& name, std::string lang) {
    std::transform(lang.begin(), lang.end(), lang.begin(), ::tolower);
    if (lang == "c++") lang = "cpp";
    if (lang == "native") lang = "cpp";
    if (lang == "wasm") lang = "rust";

    if (lang != "cpp" && lang != "rust" && lang != "lua") {
        std::cerr << "[-] Error: Unsupported language/tier '" << lang << "'. Use 'cpp', 'rust', or 'lua'." << std::endl;
        return false;
    }

    fs::path dir = name;
    if (fs::exists(dir)) {
        std::cerr << "[-] Error: Destination directory '" << name << "' already exists." << std::endl;
        return false;
    }
    fs::create_directories(dir);

    std::string tier_str = (lang == "cpp") ? "native" : (lang == "rust") ? "wasm" : "lua";
    
    // 1. Generate manifest.json
    {
        std::ofstream mf(dir / "manifest.json");
        mf << "{\n"
           << "  \"id\": \"org.aryorithm.plugin." << name << "\",\n"
           << "  \"name\": \"" << name << "\",\n"
           << "  \"version\": \"1.0.0\",\n"
           << "  \"tier\": \"" << tier_str << "\",\n"
           << "  \"author\": \"Aryorithm Developer\",\n"
           << "  \"target_protocol\": \"CUSTOM\",\n"
           << "  \"default_port\": 0\n"
           << "}\n";
    }

    if (lang == "rust") {
        fs::create_directories(dir / "src");
        
        // Cargo.toml
        {
            std::ofstream f(dir / "Cargo.toml");
            f << "[package]\n"
              << "name = \"" << name << "\"\n"
              << "version = \"1.0.0\"\n"
              << "edition = \"2021\"\n\n"
              << "[lib]\n"
              << "crate-type = [\"cdylib\"]\n\n"
              << "[dependencies]\n"
              << "sentinel-sdk-rs = { path = \"../../../tools/sdk/rust/sentinel-sdk-rs\" }\n\n"
              << "[profile.release]\n"
              << "opt-level = 3\n"
              << "lto = true\n"
              << "codegen-units = 1\n"
              << "panic = \"abort\"\n"
              << "strip = true\n";
        }

        // src/lib.rs
        {
            std::ofstream f(dir / "src" / "lib.rs");
            f << "#![no_std]\n"
              << "use core::panic::PanicInfo;\n"
              << "use sentinel_sdk_rs::{PacketView, Verdict};\n\n"
              << "#[panic_handler]\n"
              << "fn panic(_info: &PanicInfo) -> ! {\n"
              << "    loop {}\n"
              << "}\n\n"
              << "// Exported C-ABI entry point expected by Sentinel WasmSandbox\n"
              << "#[no_mangle]\n"
              << "pub extern \"C\" fn sentinel_dissect(pkt_ptr: *const u8, len: u32) -> i32 {\n"
              << "    let pkt = unsafe { PacketView::from_raw(pkt_ptr, len as usize) };\n"
              << "    if pkt.is_empty() {\n"
              << "        return Verdict::Pass as i32;\n"
              << "    }\n\n"
              << "    // Example: Drop frames containing 0xDEADBEEF\n"
              << "    if pkt.len() >= 4 && pkt.read_be32(0) == Some(0xDEADBEEF) {\n"
              << "        return Verdict::KernelDrop as i32;\n"
              << "    }\n\n"
              << "    Verdict::Pass as i32\n"
              << "}\n";
        }

        // build.sh helper
        {
            std::ofstream f(dir / "build.sh");
            f << "#!/usr/bin/env bash\n"
              << "set -e\n"
              << "cargo build --target wasm32-unknown-unknown --release\n"
              << "echo '[+] Compiled: target/wasm32-unknown-unknown/release/" << name << ".wasm'\n";
            fs::permissions(dir / "build.sh", fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read);
        }

    } else if (lang == "cpp") {
        fs::create_directories(dir / "src");

        // CMakeLists.txt
        {
            std::ofstream f(dir / "CMakeLists.txt");
            f << "cmake_minimum_required(VERSION 3.20)\n"
              << "project(sentinel_plugin_" << name << " CXX)\n\n"
              << "set(CMAKE_CXX_STANDARD 20)\n"
              << "set(CMAKE_CXX_STANDARD_REQUIRED ON)\n"
              << "set(CMAKE_CXX_VISIBILITY_PRESET hidden)\n"
              << "set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)\n\n"
              << "include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../include)\n\n"
              << "add_library(sentinel_" << name << " SHARED src/plugin.cpp)\n"
              << "set_target_properties(sentinel_" << name << " PROPERTIES PREFIX \"\")\n";
        }

        // src/plugin.cpp
        {
            std::ofstream f(dir / "src" / "plugin.cpp");
            f << "#include <sentinel/sdk/plugin.hpp>\n\n"
              << "using namespace sentinel::sdk;\n\n"
              << "static SentinelDissectorResult " << name << "_dissect(const SentinelRawPacket* raw_pkt) {\n"
              << "    if (!raw_pkt || !raw_pkt->data || raw_pkt->length < 4) {\n"
              << "        return VerdictBuilder::Pass();\n"
              << "    }\n\n"
              << "    PacketView pkt(*raw_pkt);\n"
              << "    // Threat detection logic here (sub-microsecond execution)\n"
              << "    if (pkt.read_be32(0) == 0xDEADBEEF) {\n"
              << "        return VerdictBuilder::Drop(8001, \"MALICIOUS_MAGIC_BYTES\", 1.0f)\n"
              << "            .with_tag(tags::CPS_ACTUATOR_WRITE)\n"
              << "            .build();\n"
              << "    }\n\n"
              << "    return VerdictBuilder::Pass();\n"
              << "}\n\n"
              << "static SentinelPluginDescriptor g_descriptor = {\n"
              << "    SENTINEL_SDK_MAGIC,\n"
              << "    SENTINEL_SDK_VERSION_MAJOR,\n"
              << "    SENTINEL_SDK_VERSION_MINOR,\n"
              << "    SENTINEL_TIER_NATIVE_CPP,\n"
              << "    \"org.aryorithm.plugin." << name << "\",\n"
              << "    \"" << name << "\",\n"
              << "    \"1.0.0\",\n"
              << "    \"CUSTOM\",\n"
              << "    0,\n"
              << "    0,\n"
              << "    nullptr,\n"
              << "    nullptr,\n"
              << "    " << name << "_dissect\n"
              << "};\n\n"
              << "SENTINEL_REGISTER_PLUGIN(g_descriptor)\n";
        }

        // build.sh helper
        {
            std::ofstream f(dir / "build.sh");
            f << "#!/usr/bin/env bash\n"
              << "set -e\n"
              << "mkdir -p build && cd build\n"
              << "cmake .. -DCMAKE_BUILD_TYPE=Release\n"
              << "make -j$(nproc)\n"
              << "echo '[+] Compiled: build/sentinel_" << name << ".so'\n";
            fs::permissions(dir / "build.sh", fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read);
        }

    } else if (lang == "lua") {
        // Lua rule
        {
            std::ofstream f(dir / (name + ".lua"));
            f << "local ffi = ffi or require(\"ffi\")\n\n"
              << "Rule = {\n"
              << "    id   = 7001,\n"
              << "    name = \"" << name << "\",\n"
              << "    port = 0\n"
              << "}\n\n"
              << "function Rule.inspect(pkt)\n"
              << "    if not pkt or not pkt.data then return 0 end\n"
              << "    local len = tonumber(pkt.length)\n"
              << "    if not len or len < 4 then return 0 end\n\n"
              << "    -- Check bytes for malicious pattern\n"
              << "    if pkt.data[0] == 0xDE and pkt.data[1] == 0xAD then\n"
              << "        return 3 -- SENTINEL_VERDICT_KERNEL_DROP\n"
              << "    end\n\n"
              << "    return 0 -- PASS\n"
              << "end\n";
        }
    }

    std::cout << "\033[1;32m[+] Successfully scaffolded " << tier_str 
              << " (" << lang << ") plugin in ./" << name << "/\033[0m\n"
              << "    Manifest: ./" << name << "/manifest.json\n";
    if (lang != "lua") {
        std::cout << "    Build script: ./" << name << "/build.sh\n";
    }
    return true;
}

// -----------------------------------------------------------------------------
// 2. KEYGEN COMMAND: sentinel-plugin-pack keygen <prefix>
// -----------------------------------------------------------------------------
bool cmd_keygen(const std::string& key_prefix) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) return false;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    std::string priv_path = key_prefix + "_private.pem";
    std::string pub_path = key_prefix + "_public.pem";

    FILE* fp_priv = fopen(priv_path.c_str(), "wb");
    PEM_write_PrivateKey(fp_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp_priv);

    FILE* fp_pub = fopen(pub_path.c_str(), "wb");
    PEM_write_PUBKEY(fp_pub, pkey);
    fclose(fp_pub);

    EVP_PKEY_free(pkey);
    std::cout << "[+] Generated Ed25519 keypair:\n"
              << "    Private Key: " << priv_path << "\n"
              << "    Public Key:  " << pub_path << std::endl;
    return true;
}

// -----------------------------------------------------------------------------
// 3. PACK COMMAND: sentinel-plugin-pack pack <priv_key> <tier> <manifest> <payload> <out>
// -----------------------------------------------------------------------------
bool cmd_pack(const std::string& priv_key_path,
              uint32_t tier,
              const std::string& manifest_path,
              const std::string& payload_path,
              const std::string& out_path) {
    auto manifest_data = read_file(manifest_path);
    auto payload_data = read_file(payload_path);

    if (manifest_data.empty() || payload_data.empty()) {
        std::cerr << "[-] Failed to read manifest or payload file." << std::endl;
        return false;
    }

    FILE* fp_key = fopen(priv_key_path.c_str(), "rb");
    if (!fp_key) {
        std::cerr << "[-] Cannot open private key: " << priv_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp_key, nullptr, nullptr, nullptr);
    fclose(fp_key);
    if (!pkey) return false;

    auto h_man = sha256_buffer(manifest_data.data(), manifest_data.size());
    auto h_pay = sha256_buffer(payload_data.data(), payload_data.size());

    std::vector<uint8_t> sign_input;
    sign_input.insert(sign_input.end(), h_man.begin(), h_man.end());
    sign_input.insert(sign_input.end(), h_pay.begin(), h_pay.end());

    SPluginHeader hdr;
    hdr.magic = SPLUGIN_MAGIC;
    hdr.version = SPLUGIN_VERSION;
    hdr.tier = tier;
    hdr.manifest_len = static_cast<uint32_t>(manifest_data.size());
    hdr.payload_len = static_cast<uint64_t>(payload_data.size());

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = sizeof(hdr.signature);
    EVP_DigestSign(md_ctx, hdr.signature, &sig_len, sign_input.data(), sign_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    std::ofstream out(out_path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    out.write(reinterpret_cast<const char*>(manifest_data.data()), manifest_data.size());
    out.write(reinterpret_cast<const char*>(payload_data.data()), payload_data.size());
    out.close();

    std::cout << "[+] Successfully packed and signed container: " << out_path << "\n"
              << "    Tier: " << tier << " | Manifest: " << hdr.manifest_len 
              << " bytes | Payload: " << hdr.payload_len << " bytes" << std::endl;
    return true;
}

// -----------------------------------------------------------------------------
// 4. VERIFY COMMAND: sentinel-plugin-pack verify <pub_key> <in.splugin>
// -----------------------------------------------------------------------------
bool cmd_verify(const std::string& pub_key_path, const std::string& splugin_path) {
    auto container = read_file(splugin_path);
    if (container.size() < sizeof(SPluginHeader)) {
        std::cerr << "[-] File too small to be valid .splugin" << std::endl;
        return false;
    }

    SPluginHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));

    if (hdr.magic != SPLUGIN_MAGIC) {
        std::cerr << "[-] Invalid magic header bytes!" << std::endl;
        return false;
    }

    size_t expected_sz = sizeof(SPluginHeader) + hdr.manifest_len + hdr.payload_len;
    if (container.size() != expected_sz) {
        std::cerr << "[-] Corrupt container size mismatch!" << std::endl;
        return false;
    }

    const uint8_t* man_ptr = container.data() + sizeof(SPluginHeader);
    const uint8_t* pay_ptr = man_ptr + hdr.manifest_len;

    auto h_man = sha256_buffer(man_ptr, hdr.manifest_len);
    auto h_pay = sha256_buffer(pay_ptr, hdr.payload_len);

    std::vector<uint8_t> sign_input;
    sign_input.insert(sign_input.end(), h_man.begin(), h_man.end());
    sign_input.insert(sign_input.end(), h_pay.begin(), h_pay.end());

    FILE* fp = fopen(pub_key_path.c_str(), "rb");
    if (!fp) {
        std::cerr << "[-] Cannot open public key: " << pub_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    int res = EVP_DigestVerify(md_ctx, hdr.signature, 64, sign_input.data(), sign_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (res == 1) {
        std::cout << "[VERIFIED] Signature is AUTHENTIC and tamper-free!\n"
                  << "           Tier: " << hdr.tier << " | Payload size: " 
                  << hdr.payload_len << " bytes" << std::endl;
        return true;
    } else {
        std::cerr << "[REJECTED] Cryptographic signature INVALID or container TAMPERED!" << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sentinel-plugin-pack new <name> [cpp|rust|lua]       Scaffold a new plugin project\n"
                  << "  sentinel-plugin-pack keygen <prefix>                 Generate Ed25519 developer keypair\n"
                  << "  sentinel-plugin-pack pack <priv_key> <tier> <m> <p>  Pack & sign into .splugin container\n"
                  << "  sentinel-plugin-pack verify <pub_key> <in.splugin>   Verify .splugin container signature\n";
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "new" && argc >= 3) {
        std::string lang = (argc >= 4) ? argv[3] : "cpp";
        return cmd_new(argv[2], lang) ? 0 : 1;
    } else if (cmd == "keygen" && argc >= 3) {
        return cmd_keygen(argv[2]) ? 0 : 1;
    } else if (cmd == "pack" && argc >= 7) {
        uint32_t tier = std::stoul(argv[3]);
        return cmd_pack(argv[2], tier, argv[4], argv[5], argv[6]) ? 0 : 1;
    } else if (cmd == "verify" && argc >= 4) {
        return cmd_verify(argv[2], argv[3]) ? 0 : 1;
    }

    std::cerr << "Invalid arguments. Run without arguments to see help." << std::endl;
    return 1;
}