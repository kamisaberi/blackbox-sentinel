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
std::vector<uint8_t> sha256_buffer(const uint8_t *data, size_t len);
std::string sha256_hex(const uint8_t *data, size_t len);
std::vector<uint8_t> read_binary_file(const fs::path &p);
std::string extract_pubkey_hex(const fs::path &pub_key_path);
std::string extract_pubkey_from_privkey_hex(const fs::path &priv_key_path);
std::string sign_file_bytes_hex(const fs::path &file_path, const fs::path &priv_key_path);
SavedCredentials load_saved_credentials();
std::string normalize_publish_endpoint(std::string url);

