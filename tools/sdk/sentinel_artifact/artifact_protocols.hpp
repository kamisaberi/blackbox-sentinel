#pragma once

#include "common_artifact.hpp"
#include "artifact_packaging.hpp"

// --- FUNCTION PROTOTYPES ---
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
            // Skip CSV header line
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

    slab.close();

    std::cout << "\033[1;32m[SUCCESS] Converted " << converted_rows << " records into SLAB binary dataset: "
              << out_slab_path << "\033[0m (" << fs::file_size(out_slab_path) << " bytes)\n";

    // -------------------------------------------------------------------------
    // AUTO-GENERATE COMPANION MANIFEST WITH EXACT METADATA (Dim, Format, Records)
    // -------------------------------------------------------------------------
    std::string slug_val = fs::path(out_slab_path).stem().string();
    fs::path manifest_out = fs::path(out_slab_path).parent_path() / "manifest.json";
    fs::path manifest_named_out = fs::path(out_slab_path + ".manifest.json");

    // 1. Highest priority: The enrolled author key saved from login in credentials.json
    SavedCredentials saved = load_saved_credentials();
    std::string author_pub_hex = saved.author_public_key;

    // 2. Fallback: Search developer keys on disk
    if (author_pub_hex.empty())
    {
        const char *home_env = std::getenv("HOME");
        fs::path home_path = home_env ? fs::path(home_env) : fs::path("");

        std::vector<fs::path> pub_candidates;
        pub_candidates.push_back(fs::path(out_slab_path).parent_path() / "keys" / "developer_private.pem");
        pub_candidates.push_back(fs::path(out_slab_path).parent_path() / "developer_private.pem");

        if (!home_path.empty())
        {
            pub_candidates.push_back(home_path / ".sentinel" / "keys" / "developer_private.pem");
            pub_candidates.push_back(home_path / ".sentinel" / "keys" / "developer_public.pem");
        }
        pub_candidates.push_back("/home/kami/.sentinel/keys/developer_private.pem");
        pub_candidates.push_back("/home/kami/.sentinel/keys/developer_public.pem");
        pub_candidates.push_back("/etc/sentinel/keys/developer_private.pem");

        for (const auto &p : pub_candidates)
        {
            if (fs::exists(p))
            {
                author_pub_hex = extract_pubkey_from_privkey_hex(p);
                if (author_pub_hex.empty())
                    author_pub_hex = extract_pubkey_hex(p);
                if (!author_pub_hex.empty())
                    break;
            }
        }
    }

    auto write_manifest_file = [&](const fs::path &target_path) {
        std::ofstream mf(target_path);
        mf << "{\n"
           << "  \"name\": \"" << slug_val << "\",\n"
           << "  \"slug\": \"" << slug_val << "\",\n"
           << "  \"title\": \"" << slug_val << "\",\n"
           << "  \"asset_type\": \"dataset\",\n"
           << "  \"format\": \"SLAB_BINARY\",\n"
           << "  \"dimension\": " << expected_dim << ",\n"
           << "  \"total_records\": " << converted_rows << ",\n"
           << "  \"category\": \"SCADA_ICS\",\n"
           << "  \"target_protocol\": \"MODBUS_TCP\",\n";

        if (!author_pub_hex.empty())
        {
            mf << "  \"author_public_key\": \"" << author_pub_hex << "\",\n";
        }

        mf << "  \"compliance\": [\"IEC-62443-4-2\", \"NIS2\"]\n"
           << "}\n";
        mf.close();
    };

    write_manifest_file(manifest_out);
    write_manifest_file(manifest_named_out);

    std::cout << "[+] Generated dataset manifest: " << manifest_out.string() << "\n";
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
bool cmd_synthesize_vaccine(const std::string &input_target, const std::string &out_dir_override = "")
{
    fs::path target_file = input_target;

    // If a directory was provided, pick the newest exploit_*.json file in that directory
    if (fs::is_directory(target_file))
    {
        fs::path newest_file;
        fs::file_time_type newest_time;
        bool found = false;

        for (const auto &entry : fs::directory_iterator(target_file))
        {
            if (entry.path().extension() == ".json" && entry.path().filename().string().rfind("exploit_", 0) == 0)
            {
                auto ftime = fs::last_write_time(entry);
                if (!found || ftime > newest_time)
                {
                    newest_time = ftime;
                    newest_file = entry.path();
                    found = true;
                }
            }
        }

        if (!found)
        {
            std::cerr << "[-] Error: No exploit_*.json files found in " << target_file.string() << std::endl;
            return false;
        }
        target_file = newest_file;
    }

    if (!fs::exists(target_file))
    {
        std::cerr << "[-] Error: Exploit capture file not found: " << target_file.string() << std::endl;
        return false;
    }

    std::cout << "\033[1;36m[*] [Vaccine Synthesizer] Ingesting Honeynet Exploit:\033[0m "
              << target_file.string() << "\n";

    auto json_bytes = read_binary_file(target_file);
    std::string json(reinterpret_cast<const char *>(json_bytes.data()), json_bytes.size());

    std::string proto = extract_json_field(json, "protocol");
    std::string client_ip = extract_json_field(json, "client_ip");
    std::string func_code_str = extract_json_field(json, "function_code");
    std::string payload_hex = extract_json_field(json, "payload_hex");
    std::string reason = extract_json_field(json, "reason");

    if (proto.empty())
        proto = "OT_CUSTOM";
    uint32_t func_code = func_code_str.empty() ? 0 : std::stoul(func_code_str);

    auto raw_payload = hex_to_bytes(payload_hex);

    // Build unique vaccine name
    std::string timestamp_str = target_file.stem().string();
    size_t ts_pos = timestamp_str.find('_');
    if (ts_pos != std::string::npos)
        timestamp_str = timestamp_str.substr(ts_pos + 1);
    else
        timestamp_str = std::to_string(std::time(nullptr));

    std::string pkg_name = "vaccine_" + proto + "_" + timestamp_str;
    std::transform(pkg_name.begin(), pkg_name.end(), pkg_name.begin(), ::tolower);

    fs::path out_root = out_dir_override.empty() ? fs::path("/tmp") / pkg_name : fs::path(out_dir_override) / pkg_name;
    fs::create_directories(out_root);
    fs::create_directories(out_root / "tests");
    fs::create_directories(out_root / "keys");

    // 1. Synthesize Manifest JSON
    int port = 502;
    if (proto == "S7COMM")
        port = 102;
    else if (proto == "IEC104")
        port = 2404;

    std::ofstream mf(out_root / "manifest.json");
    mf << "{\n"
       << "  \"id\": \"org.aryorithm.vaccine." << pkg_name << "\",\n"
       << "  \"name\": \"" << pkg_name << "\",\n"
       << "  \"slug\": \"" << pkg_name << "\",\n"
       << "  \"version\": \"1.0.0\",\n"
       << "  \"tier\": \"lua\",\n"
       << "  \"author\": \"Sentinel Autonomous Honeynet\",\n"
       << "  \"target_protocol\": \"" << proto << "\",\n"
       << "  \"default_port\": " << port << ",\n"
       << "  \"latency_sla_ns\": 350,\n"
       << "  \"compliance\": [\"IEC-62443-4-2\", \"AUTONOMOUS_FLEET_IMMUNIZATION\"]\n"
       << "}\n";
    mf.close();

    // 2. Synthesize Preflight Test Vector using actual captured payload
    fs::path test_vector_path = out_root / "tests" / "preflight_frame.bin";
    std::ofstream tf(test_vector_path, std::ios::binary);
    if (!raw_payload.empty())
    {
        tf.write(reinterpret_cast<const char *>(raw_payload.data()), raw_payload.size());
    }
    else
    {
        uint8_t dummy[] = {0xDE, 0xAD, 0xBE, 0xEF};
        tf.write(reinterpret_cast<const char *>(dummy), sizeof(dummy));
    }
    tf.close();

    // 3. Synthesize Tier C LuaJIT Reflex Rule
    fs::path lua_file = out_root / (pkg_name + ".lua");
    std::ofstream lf(lua_file);
    lf << "-- Automated Reflex Vaccine Synthesized by Blackbox Sentinel Honeynet\n"
       << "-- Triggered by: " << reason << " from " << client_ip << "\n"
       << "local ffi = ffi or require(\"ffi\")\n\n"
       << "Rule = {\n"
       << "    id = " << (10000 + (func_code * 10)) << ",\n"
       << "    name = \"" << pkg_name << "\",\n"
       << "    port = " << port << "\n"
       << "}\n\n"
       << "function Rule.inspect(pkt)\n"
       << "    if not pkt or not pkt.data then return 0 end\n"
       << "    local len = tonumber(pkt.length)\n"
       << "    if not len or len < 4 then return 0 end\n";

    if (proto == "MODBUS")
    {
        lf << "    -- Modbus TCP Check: len >= 8 and function code == " << func_code << "\n"
           << "    if len >= 8 and pkt.data[2] == 0x00 and pkt.data[3] == 0x00 and pkt.data[7] == " << func_code << " then\n"
           << "        return 3 -- Fast in-kernel DROP\n"
           << "    end\n";
    }
    else if (proto == "S7COMM")
    {
        lf << "    -- S7Comm Check: COTP TPKT + S7 Function Code " << func_code << "\n"
           << "    if len >= 18 and pkt.data[0] == 0x03 and pkt.data[7] == 0x32 and pkt.data[17] == " << func_code << " then\n"
           << "        return 3 -- Fast in-kernel DROP\n"
           << "    end\n";
    }
    else if (proto == "IEC104")
    {
        lf << "    -- IEC 60870-5-104 Control Frame Check\n"
           << "    if len >= 6 and pkt.data[0] == 0x68 and pkt.data[2] == " << func_code << " then\n"
           << "        return 3 -- Fast in-kernel DROP\n"
           << "    end\n";
    }
    else
    {
        lf << "    return 0\n";
    }

    lf << "    return 0\n"
       << "end\n";
    lf.close();

    // 4. Generate Local Ed25519 Keypair if needed
    fs::path priv_key = out_root / "keys" / "ed25519_private.pem";
    cmd_keygen((out_root / "keys" / "ed25519").string());

    // 5. Pack and Seal the .spkg Vaccine
    fs::path spkg_out = out_root / (pkg_name + ".spkg");
    std::cout << "[+] Packing and signing synthesized vaccine into: " << spkg_out.string() << "\n";
    if (!cmd_pack_dir(out_root.string(), priv_key.string()))
    {
        std::cerr << "[-] Error: Failed to pack synthesized vaccine.\n";
        return false;
    }

    // 6. Pre-flight Verification Check
    if (cmd_test_preflight(spkg_out.string()))
    {
        std::cout << "\033[1;32m[+] VACCINE SYNTHESIS COMPLETE: " << spkg_out.string() << "\033[0m\n"
                  << "    Ready for sub-50ms fleet broadcast via sentinel-nexus!\n";
        return true;
    }

    return false;
}

