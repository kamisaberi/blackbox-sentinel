#pragma once

#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "sentinel/hardware/tpm_enrollment.hpp"
#include "sentinel/subsystems/trism_firewall.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace fs = std::filesystem;

#define SPKG_MAGIC 0x474B50534F595241ULL // "ARYOSPKG"
#define SPKG_VERSION 1

struct SpkgHeader
{
    uint64_t magic{SPKG_MAGIC};
    uint32_t version{SPKG_VERSION};
    uint32_t tier{0};         // 0=Native C++, 1=Rust Wasm, 2=LuaJIT
    uint8_t signature[64]{0}; // Ed25519 signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
    uint64_t source_len{0};
    uint32_t test_vector_len{0};
    uint32_t reserved{0};
} __attribute__((packed));

struct SavedCredentials
{
    std::string api_key;
    std::string jwt_token;
    std::string hub_url;
    std::string author_public_key;
};

struct SbomArtifact
{
    std::string path;
    uint64_t inode;
    std::string sha256;
    size_t size;
};


static std::string g_hub_url = "https://backend.aryorithm.com";

// --- FUNCTION PROTOTYPES & UTILITIES ---



// --- FUNCTION PROTOTYPES ---

static SbomArtifact compute_artifact_sbom(const fs::path &p)
{
    SbomArtifact a{};
    a.path = p.string();
    if (!fs::exists(p))
        return a;

    struct stat st{};
    if (stat(p.c_str(), &st) == 0)
    {
        a.inode = st.st_ino;
        a.size = st.st_size;
    }
    auto bytes = read_binary_file(p);
    a.sha256 = sha256_hex(bytes.data(), bytes.size());
    return a;
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

static std::string trim(const std::string &s)
{
    auto start = s.find_first_not_of(" \t\r\n\"-");
    if (start == std::string::npos)
        return "";
    auto end = s.find_last_not_of(" \t\r\n\"");
    return s.substr(start, end - start + 1);
}

fs::path get_credentials_path()
{
    const char *home = std::getenv("HOME");
    if (home)
    {
        fs::path p = fs::path(home) / ".sentinel";
        fs::create_directories(p);
        return p / "credentials.json";
    }
    return fs::path("/etc/sentinel/credentials.json");
}

static SavedCredentials load_saved_credentials()
{
    SavedCredentials creds{};
    fs::path cred_path = get_credentials_path();
    if (fs::exists(cred_path))
    {
        std::ifstream f(cred_path);
        std::string line;
        while (std::getline(f, line))
        {
            auto extract_field = [&](const std::string &key, std::string &target)
            {
                size_t pos = line.find("\"" + key + "\"");
                if (pos != std::string::npos)
                {
                    size_t colon = line.find(':', pos);
                    size_t start = line.find('"', colon + 1);
                    size_t end = line.find('"', start + 1);
                    if (start != std::string::npos && end != std::string::npos)
                    {
                        target = line.substr(start + 1, end - start - 1);
                    }
                }
            };
            extract_field("api_key", creds.api_key);
            extract_field("jwt_token", creds.jwt_token);
            extract_field("hub_url", creds.hub_url);
            extract_field("author_public_key", creds.author_public_key);
        }
    }
    return creds;
}

static std::string normalize_registry_url(std::string url)
{
    if (url.empty())
    {
        url = "https://backend.aryorithm.com";
    }

    // Auto-detect http scheme for localhost/IPs, https for remote domains
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

    // Append /api/v1 if not present
    if (url.rfind("/api/v1") == std::string::npos)
    {
        url += "/api/v1";
    }

    return url;
}
fs::path get_cache_root()
{
    const char *env_cache = std::getenv("SENTINEL_CACHE_DIR");
    if (env_cache && std::strlen(env_cache) > 0)
        return fs::path(env_cache);

    if (geteuid() == 0)
    {
        return fs::path("/var/cache/sentinel");
    }

    const char *home = std::getenv("HOME");
    if (home)
    {
        return fs::path(home) / ".cache" / "sentinel";
    }
    return fs::path("/tmp/sentinel_cache");
}

static std::string get_enrolled_author_pubkey_hex()
{
    // 1. Highest priority: The enrolled author key saved from login in credentials.json
    SavedCredentials creds = load_saved_credentials();
    if (!creds.author_public_key.empty())
    {
        return creds.author_public_key;
    }

    // 2. Fallback: Search developer keys on disk (supports both public and private PEM)
    const char *home = std::getenv("HOME");
    std::vector<fs::path> candidates;
    if (home)
    {
        candidates.push_back(fs::path(home) / ".sentinel" / "keys" / "developer_public.pem");
        candidates.push_back(fs::path(home) / ".sentinel" / "keys" / "developer_private.pem");
    }
    candidates.push_back("/home/kami/.sentinel/keys/developer_public.pem");
    candidates.push_back("/home/kami/.sentinel/keys/developer_private.pem");
    candidates.push_back("/etc/sentinel/keys/developer_public.pem");
    candidates.push_back("/etc/sentinel/keys/developer_private.pem");

    for (const auto &p : candidates)
    {
        if (fs::exists(p))
        {
            FILE *fp = fopen(p.c_str(), "rb");
            if (fp)
            {
                EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
                if (!pkey)
                {
                    fseek(fp, 0, SEEK_SET);
                    pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
                }
                fclose(fp);

                if (pkey)
                {
                    size_t len = 32;
                    uint8_t raw_key[32];
                    if (EVP_PKEY_get_raw_public_key(pkey, raw_key, &len) == 1)
                    {
                        EVP_PKEY_free(pkey);
                        std::ostringstream ss;
                        for (size_t i = 0; i < len; ++i)
                        {
                            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(raw_key[i]);
                        }
                        return ss.str();
                    }
                    EVP_PKEY_free(pkey);
                }
            }
        }
    }
    return "";
}
bool resolve_cached_asset(const std::string &category,
                          const std::string &filename,
                          fs::path &out_staged_path,
                          bool force_refresh = false)
{
    fs::path cache_dir = get_cache_root() / category;
    fs::create_directories(cache_dir);
    fs::path cached_file = cache_dir / filename;

    // STEP 1: CHECK LOCAL CACHE (CACHE HIT)
    if (!force_refresh && fs::exists(cached_file) && fs::file_size(cached_file) > 0)
    {
        std::cout << "  \033[1;32m[CACHE HIT]\033[0m " << filename
                  << " (0 ms, 0 network) -> " << cached_file.string() << "\n";
        out_staged_path = cached_file;
        return true;
    }

    // STEP 2: CACHE MISS -> ATTEMPT PULL FROM REGISTRY
    std::cout << "  \033[1;33m[CACHE MISS]\033[0m Resolving " << filename << "...\n";

    std::vector<fs::path> local_fallbacks = {
        fs::path("/home/kami/sentinel-hub/dist") / category / filename,
        fs::path("/home/kami/sentinel-hub/dist") / filename,
        fs::path("/home/kami/sentinel-matrix/shared/datasets") / filename,
        fs::path("rules/lua") / filename,
        fs::path("models") / filename};

    bool resolved = false;
    for (const auto &fb : local_fallbacks)
    {
        if (fs::exists(fb) && !fs::is_directory(fb))
        {
            fs::copy_file(fb, cached_file, fs::copy_options::overwrite_existing);
            resolved = true;
            std::cout << "      --> Synced into cache from local source: " << fb.string() << "\n";
            break;
        }
    }

    // --- REPLACE REMOTE FETCH & STUB PORTION OF resolve_cached_asset() WITH THIS BLOCK ---
    if (!resolved)
    {
        SavedCredentials creds = load_saved_credentials();
        std::string effective_url = !creds.hub_url.empty() ? creds.hub_url : g_hub_url;
        std::string base_api = normalize_registry_url(effective_url);
        std::string auth_hdr = !creds.api_key.empty() ? ("-H \"Authorization: Bearer " + creds.api_key + "\" ") : "";

        std::string asset_type = (category.back() == 's') ? category.substr(0, category.size() - 1) : category;
        std::string pure_slug = fs::path(filename).stem().string();
        if (pure_slug.size() > 4 && pure_slug.rfind(".tar") == pure_slug.size() - 4)
            pure_slug = pure_slug.substr(0, pure_slug.size() - 4);

        // Stage 1: Try Canonical Unified Route (/hub/assets/{type}/{slug}/download)
        std::string download_url = base_api + "/hub/assets/" + asset_type + "/" + pure_slug + "/download";
        std::cout << "      --> [Stage 1] Downloading from Canonical Route: " << download_url << "\n";

        std::string curl_cmd = "curl -sSL -f " + auth_hdr + "-o \"" + cached_file.string() + "\" \"" + download_url + "\" 2>/dev/null";
        int ret = std::system(curl_cmd.c_str());

        // Stage 2: Fallback to Tolerant Root Alias Route (/{category}/{filename}/download)
        if (ret != 0 || !fs::exists(cached_file) || fs::file_size(cached_file) == 0)
        {
            download_url = base_api + "/" + category + "/" + filename + "/download";
            std::cout << "      --> [Stage 2] Falling back to Root Alias: " << download_url << "\n";
            curl_cmd = "curl -sSL -f " + auth_hdr + "-o \"" + cached_file.string() + "\" \"" + download_url + "\" 2>/dev/null";
            ret = std::system(curl_cmd.c_str());
        }

        if (ret == 0 && fs::exists(cached_file) && fs::file_size(cached_file) > 0)
        {
            resolved = true;
            std::cout << "      --> \033[1;32mDownload successful & written to cache.\033[0m\n";
        }
    }

    if (!resolved)
    {
        std::cerr << "      --> \033[1;31m[-] Error: Unable to resolve " << filename << " from cache or registry.\033[0m\n";
        return false;
    }

    out_staged_path = cached_file;
    return true;
}

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

[[maybe_unused]] static std::string sha256_hex(const uint8_t *data, size_t len)
{
    auto h = sha256_buffer(data, len);
    std::ostringstream ss;
    for (uint8_t b : h)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

// [PLACEHOLDER: Implementations of load_saved_credentials, resolve_cached_asset, get_enrolled_author_pubkey_hex remain identical to previous turns]