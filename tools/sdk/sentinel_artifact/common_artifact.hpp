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

static SavedCredentials load_saved_credentials()
{
    SavedCredentials creds{};
    const char *home = std::getenv("HOME");
    std::vector<fs::path> cred_paths;
    if (home)
        cred_paths.push_back(fs::path(home) / ".sentinel" / "credentials.json");
    cred_paths.push_back("/etc/sentinel/credentials.json");

    for (const auto &p : cred_paths)
    {
        if (fs::exists(p))
        {
            std::ifstream f(p);
            std::string line;
            while (std::getline(f, line))
            {
                auto extract_field = [&](const std::string &key, std::string &target) {
                    size_t pos = line.find("\"" + key + "\"");
                    if (pos != std::string::npos) {
                        size_t colon = line.find(':', pos);
                        size_t start = line.find('"', colon + 1);
                        size_t end = line.find('"', start + 1);
                        if (start != std::string::npos && end != std::string::npos) {
                            target = line.substr(start + 1, end - start - 1);
                        }
                    }
                };
                extract_field("api_key", creds.api_key);
                extract_field("hub_url", creds.hub_url);
                extract_field("author_public_key", creds.author_public_key);
            }
        }
    }
    return creds;
}
static std::string normalize_publish_endpoint(std::string url)
{
    if (url.empty())
    {
        url = "https://backend.aryorithm.com";
    }

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

    while (!url.empty() && url.back() == '/')
    {
        url.pop_back();
    }

    if (url.rfind("/publish") != std::string::npos)
    {
        return url;
    }
    if (url.rfind("/api/v1/hub") != std::string::npos)
    {
        return url + "/publish";
    }
    if (url.rfind("/api/v1") != std::string::npos)
    {
        return url + "/hub/publish";
    }

    return url + "/api/v1/hub/publish";
}

static std::string extract_json_field(const std::string &json, const std::string &key)
{
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos)
        return "";
    size_t colon = json.find(':', pos);
    if (colon == std::string::npos)
        return "";
    size_t start = json.find_first_not_of(" \t\r\n", colon + 1);
    if (start == std::string::npos)
        return "";

    if (json[start] == '"')
    {
        size_t end = json.find('"', start + 1);
        if (end != std::string::npos)
            return json.substr(start + 1, end - start - 1);
    }
    else
    {
        size_t end = json.find_first_of(",}\r\n", start);
        if (end != std::string::npos)
            return json.substr(start, end - start);
    }
    return "";
}

static std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2)
    {
        std::string byte_str = hex.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}
