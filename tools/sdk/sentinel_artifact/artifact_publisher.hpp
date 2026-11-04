#pragma once

#include "common_artifact.hpp"

// --- FUNCTION PROTOTYPE ---
bool cmd_publish(const std::string &file_path, std::string token, std::string hub_url)
{
    if (!fs::exists(file_path))
    {
        std::cerr << "[-] Error: Artifact file to publish not found: " << file_path << std::endl;
        return false;
    }

    SavedCredentials saved_creds = load_saved_credentials();

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

    if (hub_url.empty())
    {
        hub_url = !saved_creds.hub_url.empty() ? saved_creds.hub_url : "https://backend.aryorithm.com";
    }

    std::string base_endpoint = normalize_publish_endpoint(hub_url);
    std::string ext = fs::path(file_path).extension().string();

    std::string asset_type = "package";
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
    else if (ext == ".blueprint")
    {
        asset_type = "blueprint";
    }

    // Direct blueprints to dedicated /api/v1/hub/blueprints/publish
    std::string upload_endpoint = base_endpoint;
    if (asset_type == "blueprint")
    {
        std::string base_no_pub = base_endpoint;
        size_t pos_pub = base_no_pub.rfind("/publish");
        if (pos_pub != std::string::npos)
        {
            base_no_pub = base_no_pub.substr(0, pos_pub);
        }
        upload_endpoint = base_no_pub + "/blueprints/publish";
    }

    // 1. Search for Signing Key
    const char *home_env = std::getenv("HOME");
    fs::path home_path = home_env ? fs::path(home_env) : fs::path("");

    std::vector<fs::path> key_candidates = {
        fs::path(file_path).parent_path() / "keys" / "developer_private.pem",
        fs::path(file_path).parent_path() / "keys" / "ed25519_private.pem",
        fs::path(file_path).parent_path() / "ed25519_private.pem",
        fs::path(file_path).parent_path() / "developer_private.pem"};

    if (!home_path.empty())
    {
        key_candidates.push_back(home_path / ".sentinel" / "keys" / "developer_private.pem");
        key_candidates.push_back(home_path / ".sentinel" / "keys" / "ed25519_private.pem");
    }

    key_candidates.push_back("/etc/sentinel/keys/developer_private.pem");
    key_candidates.push_back("/etc/sentinel/keys/ed25519_private.pem");

    fs::path priv_key_path;
    for (const auto &k : key_candidates)
    {
        if (fs::exists(k) && !fs::is_directory(k))
        {
            priv_key_path = k;
            break;
        }
    }

    // Auto-generate developer keypair if none found
    if (priv_key_path.empty())
    {
        fs::path dev_dir = !home_path.empty() ? (home_path / ".sentinel" / "keys") : fs::path("/tmp/.sentinel_keys");
        fs::create_directories(dev_dir);
        std::string key_prefix = (dev_dir / "developer").string();
        std::cout << "[*] No signing key found. Auto-generating developer Ed25519 keypair at " << key_prefix << "...\n";
        cmd_keygen(key_prefix);
        priv_key_path = key_prefix + "_private.pem";
    }

    std::string sig_hex = "";
    if (!priv_key_path.empty())
    {
        std::cout << "[+] Signing artifact bytes with key: " << priv_key_path.string() << "\n";
        sig_hex = sign_file_bytes_hex(file_path, priv_key_path);
    }

    // Direct derivation of author public key from private key
    std::string clean_author_key = "";
    if (!priv_key_path.empty())
    {
        clean_author_key = extract_pubkey_from_privkey_hex(priv_key_path);
    }
    if (clean_author_key.empty() && !saved_creds.author_public_key.empty())
    {
        clean_author_key = saved_creds.author_public_key;
    }

    // 2. Normalize Slug
    std::string slug_val = fs::path(file_path).stem().string();
    if (slug_val.size() > 4 && slug_val.rfind(".tar") == slug_val.size() - 4)
    {
        slug_val = slug_val.substr(0, slug_val.size() - 4);
    }
    if (slug_val.rfind("scenario_", 0) == 0)
    {
        slug_val = slug_val.substr(9);
    }
    if (slug_val.rfind("blueprint_", 0) == 0)
    {
        slug_val = slug_val.substr(10);
    }

    // 3. Assemble Manifest (Companion on disk wins, else synthesizes schema-aware defaults)
    std::string manifest_json;

    fs::path companion_mf = fs::path(file_path).parent_path() / "manifest.json";
    fs::path companion_named_mf = file_path + ".manifest.json";

    if (fs::exists(companion_named_mf))
    {
        auto mf_b = read_binary_file(companion_named_mf);
        manifest_json = std::string(reinterpret_cast<const char *>(mf_b.data()), mf_b.size());
        std::cout << "[+] Ingested companion manifest: " << companion_named_mf.string() << "\n";
    }
    else if (fs::exists(companion_mf))
    {
        auto mf_b = read_binary_file(companion_mf);
        manifest_json = std::string(reinterpret_cast<const char *>(mf_b.data()), mf_b.size());
        std::cout << "[+] Ingested companion manifest: " << companion_mf.string() << "\n";
    }
    else
    {
        std::ostringstream ss;
        ss << "{\n"
           << "  \"name\": \"" << slug_val << "\",\n"
           << "  \"slug\": \"" << slug_val << "\",\n"
           << "  \"title\": \"" << slug_val << "\",\n"
           << "  \"version\": \"1.0.0\",\n"
           << "  \"asset_type\": \"" << asset_type << "\",\n";

        if (asset_type == "dataset")
        {
            ss << "  \"format\": \"SLAB\",\n"
               << "  \"dimension\": 32,\n"
               << "  \"category\": \"SCADA_ICS\",\n"
               << "  \"target_protocol\": \"MODBUS_TCP\",\n";
        }
        else if (asset_type == "model")
        {
            ss << "  \"format\": \"ONNX\",\n"
               << "  \"precision\": \"INT8\",\n"
               << "  \"domain\": \"SCADA_ICS\",\n"
               << "  \"target_protocol\": \"MODBUS_TCP\",\n";
        }
        else if (asset_type == "pcap")
        {
            ss << "  \"category\": \"SCADA_ICS\",\n"
               << "  \"target_protocol\": \"MODBUS_TCP\",\n"
               << "  \"attack_type\": \"RECON\",\n"
               << "  \"source_origin\": \"TESTBED\",\n";
        }
        else if (asset_type == "scenario")
        {
            ss << "  \"target_sector\": \"CRITICAL_INFRASTRUCTURE\",\n"
               << "  \"sector\": \"CRITICAL_INFRASTRUCTURE\",\n"
               << "  \"complexity\": \"INTERMEDIATE\",\n"
               << "  \"category\": \"SCADA_ICS\",\n";
        }
        else if (asset_type == "blueprint")
        {
            ss << "  \"target_site\": \"Site-" << slug_val << "\",\n"
               << "  \"target_arch\": \"x86_64\",\n"
               << "  \"industry\": \"POWER_GRID\",\n";
        }

        if (!clean_author_key.empty())
        {
            ss << "  \"author_public_key\": \"" << clean_author_key << "\",\n";
        }
        ss << "  \"compliance\": [\"IEC-62443-4-2\", \"NIS2\"]\n"
           << "}";
        manifest_json = ss.str();
    }

    // For .spkg containers, inherit internal manifest and signature if available
    auto container = read_binary_file(file_path);
    if (ext == ".spkg" && container.size() >= sizeof(SpkgHeader))
    {
        SpkgHeader hdr;
        std::memcpy(&hdr, container.data(), sizeof(hdr));
        if (hdr.magic == SPKG_MAGIC)
        {
            if (sig_hex.empty())
            {
                std::ostringstream sig_ss;
                for (int i = 0; i < 64; ++i)
                {
                    sig_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hdr.signature[i]);
                }
                sig_hex = sig_ss.str();
            }

            if (hdr.manifest_len > 0 && container.size() >= sizeof(SpkgHeader) + hdr.manifest_len)
            {
                manifest_json = std::string(reinterpret_cast<const char *>(container.data() + sizeof(SpkgHeader)), hdr.manifest_len);
            }
        }
    }

    // Ensure slug is present
    if (manifest_json.find("\"slug\"") == std::string::npos)
    {
        size_t first_brace = manifest_json.find('{');
        if (first_brace != std::string::npos)
        {
            manifest_json.insert(first_brace + 1, "\n  \"slug\": \"" + slug_val + "\",");
        }
    }

    // Inject author_public_key if missing from manifest
    if (!clean_author_key.empty() && manifest_json.find("\"author_public_key\"") == std::string::npos)
    {
        size_t last_brace = manifest_json.rfind('}');
        if (last_brace != std::string::npos)
        {
            std::string injection = ",\n  \"author_public_key\": \"" + clean_author_key + "\"\n}";
            manifest_json.replace(last_brace, 1, injection);
        }
    }

    std::string manifest_tmp = "/tmp/sentinel_manifest_temp.json";
    std::ofstream mf_out(manifest_tmp);
    mf_out << manifest_json;
    mf_out.close();

    std::cout << "[*] Initiating publish for " << file_path << " (" << ext << ") to " << upload_endpoint << "...\n"
              << "    ├── Asset Type : " << asset_type << "\n"
              << "    ├── Signature  : " << sig_hex.substr(0, 16) << "...\n"
              << "    └── Manifest   : " << manifest_json.substr(0, 60) << "...\n";

    std::string response_file = "/tmp/sentinel_pub_resp.txt";

    // Format curl multipart request based on endpoint
    std::string curl_cmd;
    if (asset_type == "blueprint")
    {
        curl_cmd = "curl -sSL --max-time 15 --connect-timeout 5 -w \"\\n%{http_code}\" -X POST \"" + upload_endpoint + "\" " +
                   "-H \"Authorization: Bearer " + token + "\" " +
                   "-F \"file=@" + file_path + "\" " +
                   "-F \"signature=" + sig_hex + "\" " +
                   "-F \"manifest=<" + manifest_tmp + "\" > " + response_file + " 2>&1";
    }
    else
    {
        curl_cmd = "curl -sSL --max-time 15 --connect-timeout 5 -w \"\\n%{http_code}\" -X POST \"" + upload_endpoint + "\" " +
                   "-H \"Authorization: Bearer " + token + "\" " +
                   "-F \"file=@" + file_path + "\" " +
                   "-F \"asset_type=" + asset_type + "\" " +
                   "-F \"signature=" + sig_hex + "\" " +
                   "-F \"manifest=<" + manifest_tmp + "\" > " + response_file + " 2>&1";
    }

    std::cout << "    --> Executing upload stream to Hub Intake API...\n";
    int ret = std::system(curl_cmd.c_str());
    (void)ret;

    fs::remove(manifest_tmp);

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
        std::cerr << "\033[1;31m[-] Error 422 Unprocessable Entity: Server rejected schema.\033[0m\n"
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

