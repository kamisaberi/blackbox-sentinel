#pragma once

#include <unistd.h>
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
    uint8_t signature[64]{0}; // Ed25519 digital signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
    uint64_t source_len{0};
    uint32_t test_vector_len{0};
    uint32_t reserved{0};
} __attribute__((packed));

struct SlabRecordHeader
{
    uint32_t magic;        // 0x534C4142
    uint32_t event_id;     // Monotonic sequence ID
    uint32_t ground_truth; // 0 = Benign, 1 = Attack
    uint32_t tensor_dim;   // Number of Float32 features
} __attribute__((packed));

struct SavedCredentials
{
    std::string api_key;
    std::string jwt_token;
    std::string hub_url;
    std::string author_public_key;
};

// --- CRYPTOGRAPHIC & FILE HELPER PROTOTYPES ---
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

static std::string extract_pubkey_hex(const fs::path &pub_key_path)
{
    FILE *fp = fopen(pub_key_path.c_str(), "rb");
    if (!fp)
        return "";
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey)
        return "";

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
    return "";
}

static std::string extract_pubkey_from_privkey_hex(const fs::path &priv_key_path)
{
    FILE *fp = fopen(priv_key_path.c_str(), "rb");
    if (!fp) return "";
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) return "";

    size_t len = 32;
    uint8_t raw_key[32];
    std::string hex_str = "";
    if (EVP_PKEY_get_raw_public_key(pkey, raw_key, &len) == 1)
    {
        std::ostringstream ss;
        for (size_t i = 0; i < len; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(raw_key[i]);
        }
        hex_str = ss.str();
    }
    EVP_PKEY_free(pkey);
    return hex_str;
}


static std::string sign_file_bytes_hex(const fs::path &file_path, const fs::path &priv_key_path)
{
    auto file_bytes = read_binary_file(file_path);
    if (file_bytes.empty() || !fs::exists(priv_key_path))
        return "";

    FILE *fp = fopen(priv_key_path.c_str(), "rb");
    if (!fp)
        return "";

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey)
        return "";

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    uint8_t sig[64];
    size_t sig_len = sizeof(sig);
    if (EVP_DigestSign(md_ctx, sig, &sig_len, file_bytes.data(), file_bytes.size()) != 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    std::ostringstream ss;
    for (size_t i = 0; i < sig_len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sig[i]);
    }
    return ss.str();
}

SavedCredentials load_saved_credentials();
std::string normalize_publish_endpoint(std::string url);

