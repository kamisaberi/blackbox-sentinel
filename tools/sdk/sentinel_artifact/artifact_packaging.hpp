#pragma once

#include "common_artifact.hpp"

// --- FUNCTION PROTOTYPES ---
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
           << "  \"slug\": \"" << name << "\",\n"
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

bool cmd_pack_dir(const std::string &dir_str, const std::string &key_override)
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

    // 1. Locate Signing Key (Prioritize explicit override, then project, then global ~/.sentinel/keys/)
    fs::path key_path = key_override;
    if (key_path.empty())
    {
        const char *home = std::getenv("HOME");
        std::vector<fs::path> candidates;
        candidates.push_back(target_dir / "keys" / "developer_private.pem");
        candidates.push_back(target_dir / "keys" / "ed25519_private.pem");
        candidates.push_back(target_dir / "ed25519_private.pem");

        if (home)
        {
            candidates.push_back(fs::path(home) / ".sentinel" / "keys" / "developer_private.pem");
            candidates.push_back(fs::path(home) / ".sentinel" / "keys" / "ed25519_private.pem");
        }
        candidates.push_back("/etc/sentinel/keys/developer_private.pem");
        candidates.push_back("/etc/sentinel/keys/ed25519_private.pem");

        for (const auto &k : candidates)
        {
            if (fs::exists(k) && !fs::is_directory(k))
            {
                key_path = k;
                break;
            }
        }
    }

    if (key_path.empty() || !fs::exists(key_path))
    {
        const char *home = std::getenv("HOME");
        fs::path p_dir = home ? (fs::path(home) / ".sentinel" / "keys") : (target_dir / "keys");
        fs::create_directories(p_dir);
        std::string prefix = (p_dir / "developer").string();
        std::cout << "[*] No author key found. Enrolling persistent Ed25519 keypair in " << p_dir.string() << "...\n";
        cmd_keygen(prefix);
        key_path = prefix + "_private.pem";
    }

    // Direct derivation of 64-char hex public key from private key
    std::string clean_hex_key = extract_pubkey_from_privkey_hex(key_path);

    // If ~/.sentinel/credentials.json has an enrolled key, prioritize it for the manifest
    SavedCredentials saved = load_saved_credentials();
    if (!saved.author_public_key.empty())
    {
        clean_hex_key = saved.author_public_key;
    }

    // 2. Read and auto-inject 64-char Hex author_public_key and slug into manifest if missing
    auto mf_bytes = read_binary_file(manifest_path);
    std::string manifest_str(reinterpret_cast<const char *>(mf_bytes.data()), mf_bytes.size());
    bool manifest_updated = false;

    if (!clean_hex_key.empty() && manifest_str.find("author_public_key") == std::string::npos)
    {
        size_t last_brace = manifest_str.rfind('}');
        if (last_brace != std::string::npos)
        {
            std::string injected = ",\n  \"author_public_key\": \"" + clean_hex_key + "\"\n}";
            manifest_str.replace(last_brace, 1, injected);
            manifest_updated = true;
            std::cout << "[+] Automatically enrolled 64-char Hex author_public_key into manifest.json\n";
        }
    }

    std::string proj_name = target_dir.filename().string();
    if (proj_name == ".")
        proj_name = fs::current_path().filename().string();

    if (manifest_str.find("\"slug\"") == std::string::npos)
    {
        size_t last_brace = manifest_str.rfind('}');
        if (last_brace != std::string::npos)
        {
            std::string injected = ",\n  \"slug\": \"" + proj_name + "\"\n}";
            manifest_str.replace(last_brace, 1, injected);
            manifest_updated = true;
            std::cout << "[+] Automatically enrolled slug into manifest.json\n";
        }
    }

    if (manifest_updated)
    {
        std::ofstream mf_out(manifest_path);
        mf_out << manifest_str;
        mf_out.close();
        mf_bytes = read_binary_file(manifest_path);
    }

    uint32_t tier = SPKG_TIER_WASM;
    if (manifest_str.find("\"tier\": \"native\"") != std::string::npos || manifest_str.find("\"tier\": \"cpp\"") != std::string::npos)
    {
        tier = SPKG_TIER_NATIVE;
    }
    else if (manifest_str.find("\"tier\": \"lua\"") != std::string::npos)
    {
        tier = SPKG_TIER_LUA;
    }

    // 3. Locate Payload Binary
    fs::path payload_path;
    if (tier == SPKG_TIER_WASM)
    {
        std::vector<fs::path> candidates = {
            target_dir / "target" / "wasm32-unknown-unknown" / "release" / (proj_name + ".wasm"),
            target_dir / (proj_name + ".wasm"),
            target_dir / "plugin.wasm"};
        for (const auto &p : candidates)
        {
            if (fs::exists(p)) { payload_path = p; break; }
        }
        if (payload_path.empty())
        {
            for (const auto &entry : fs::recursive_directory_iterator(target_dir))
            {
                if (entry.path().extension() == ".wasm") { payload_path = entry.path(); break; }
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
            if (fs::exists(p)) { payload_path = p; break; }
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
            if (fs::exists(p)) { payload_path = p; break; }
        }
    }

    if (payload_path.empty() || !fs::exists(payload_path))
    {
        std::cerr << "[-] Error: Compiled payload binary not found in " << target_dir.string() << "\n";
        return false;
    }

    // 4. Locate Source Code File
    fs::path source_path;
    if (fs::exists(target_dir / "src" / "lib.rs"))
        source_path = target_dir / "src" / "lib.rs";
    else if (fs::exists(target_dir / "src" / "plugin.cpp"))
        source_path = target_dir / "src" / "plugin.cpp";
    else if (fs::exists(target_dir / (proj_name + ".lua")))
        source_path = target_dir / (proj_name + ".lua");

    // 5. Locate Pre-Flight Test Vector
    fs::path test_pkt_path = target_dir / "tests" / "preflight_frame.bin";
    if (!fs::exists(test_pkt_path))
    {
        fs::create_directories(target_dir / "tests");
        std::ofstream tf(test_pkt_path, std::ios::binary);
        uint8_t sample_frame[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
        tf.write(reinterpret_cast<const char *>(sample_frame), sizeof(sample_frame));
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
bool cmd_inspect(const std::string &spkg_path);
bool cmd_verify(const std::string &pub_key_path, const std::string &spkg_path);
bool cmd_extract_source(const std::string &spkg_path, const std::string &out_source_file);
bool cmd_test_preflight(const std::string &spkg_path);
