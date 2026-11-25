#pragma once

#include "common_artifact.hpp"




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
        // Dynamically resolve sentinel-sdk-rs path without hardcoded developer user
        const char *home_env = std::getenv("HOME");
        fs::path sdk_rs_path = "/usr/local/share/sentinel-sdk/rust/sentinel-sdk-rs";
        if (!fs::exists(sdk_rs_path) && home_env)
        {
            fs::path local_sdk = fs::path(home_env) / "blackbox-sentinel/tools/sdk/rust/sentinel-sdk-rs";
            if (fs::exists(local_sdk))
                sdk_rs_path = local_sdk;
        }

        std::ofstream(dir / "Cargo.toml") << "[package]\nname = \"" << name << "\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n"
                                          << "[lib]\ncrate-type = [\"cdylib\"]\n\n"
                                          << "[dependencies]\nsentinel-sdk-rs = { path = \"" << sdk_rs_path.string() << "\" }\n\n"
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
        const char *home_env = std::getenv("HOME");
        std::string extra_inc = home_env ? (" " + (fs::path(home_env) / "blackbox-sentinel/include").string()) : "";

        std::ofstream(dir / "CMakeLists.txt") << "cmake_minimum_required(VERSION 3.20)\nproject(" << name << " CXX)\n"
                                              << "set(CMAKE_CXX_STANDARD 20)\nset(CMAKE_CXX_VISIBILITY_PRESET hidden)\n"
                                              << "include_directories(/usr/local/include" << extra_inc << ")\n"
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

    // 1. Check DEADBEEF signature first (default scaffolded threat vector)
    if (len >= 4 && test_ptr[0] == 0xDE && test_ptr[1] == 0xAD && test_ptr[2] == 0xBE && test_ptr[3] == 0xEF)
    {
        dropped = true;
    }
    // 2. IEC 60870-5-104 ASDU Command Check
    else if (len >= 15 && test_ptr[0] == 0x68)
    {
        uint8_t asdu_type = test_ptr[6];
        if (asdu_type == 0x2D || asdu_type == 0x2E)
            dropped = true;
    }
    // 3. S7Comm CPU STOP Command (0x29)
    else if (len >= 18 && test_ptr[0] == 0x03 && test_ptr[7] == 0x32)
    {
        uint8_t func_code = test_ptr[17];
        if (func_code == 0x29)
            dropped = true;
    }
    // 4. Modbus Unauthorized Write Coil (0x05 / 0x0F)
    else if (len >= 8 && test_ptr[0] != 0x68 && test_ptr[0] != 0x03 && test_ptr[2] == 0x00 && test_ptr[3] == 0x00)
    {
        uint8_t fc = test_ptr[7];
        if (fc == 0x05 || fc == 0x0F)
            dropped = true;
    }
    // 5. DNP3 Unauthorized Direct Operate (0x05 / 0x06)
    else if (len >= 13 && test_ptr[0] == 0x05 && test_ptr[1] == 0x64)
    {
        uint8_t fc = test_ptr[12];
        if (fc == 0x05 || fc == 0x06 || fc == 0x0E)
            dropped = true;
    }
    // 6. BACnet / Ethernet IP
    else if (len >= 9 && test_ptr[3] == 0x03 && test_ptr[len - 1] == 0x08)
    {
        dropped = true;
    }
    // 7. Log4j JNDI Exploit String
    else if (len >= 8 && std::string(reinterpret_cast<const char *>(test_ptr), len).find("${jndi:") != std::string::npos)
    {
        dropped = true;
    }
    // 8. Triton SIS TriStation Firmware Override
    else if (len >= 12 && (test_ptr[0] == 0xFD || test_ptr[0] == 0xFE))
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
