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

static std::string g_hub_url = "https://backend.aryorithm.com";

// --- FUNCTION PROTOTYPES & UTILITIES ---
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
fs::path get_cache_root();
std::string get_enrolled_author_pubkey_hex();
bool resolve_cached_asset(const std::string &category, const std::string &filename, fs::path &out_staged_path, bool force_refresh = false);

// [PLACEHOLDER: Implementations of load_saved_credentials, resolve_cached_asset, get_enrolled_author_pubkey_hex remain identical to previous turns]