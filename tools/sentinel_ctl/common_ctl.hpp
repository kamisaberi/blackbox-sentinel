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

SavedCredentials load_saved_credentials();
std::string normalize_registry_url(std::string url);
fs::path get_cache_root();
std::string get_enrolled_author_pubkey_hex();
bool resolve_cached_asset(const std::string &category, const std::string &filename, fs::path &out_staged_path, bool force_refresh = false);

// [PLACEHOLDER: Implementations of load_saved_credentials, resolve_cached_asset, get_enrolled_author_pubkey_hex remain identical to previous turns]