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
bool cmd_pcap_pack(const std::string &priv_key_path, const std::string &manifest_path, const std::string &in_pcap_path, const std::string &out_spcap_path);
bool cmd_synthesize_vaccine(const std::string &input_target, const std::string &out_dir_override = "");

