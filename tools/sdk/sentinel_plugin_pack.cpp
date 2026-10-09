#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define SPLUGIN_MAGIC 0x314C50534F595241ULL // "ARYOSPL1"
#define SPLUGIN_VERSION 1

enum PluginTier : uint32_t {
    TIER_NATIVE = 0,
    TIER_WASM   = 1,
    TIER_LUA    = 2
};

struct SPluginHeader {
    uint64_t magic{SPLUGIN_MAGIC};
    uint32_t version{SPLUGIN_VERSION};
    uint32_t tier{0};
    uint8_t  signature[64]{0}; // Ed25519 signature
    uint32_t manifest_len{0};
    uint64_t payload_len{0};
} __attribute__((packed));

// Compute SHA-256 over raw buffer
std::vector<uint8_t> sha256_buffer(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, hash.data(), &out_len);
    EVP_MD_CTX_free(ctx);
    return hash;
}

// Read entire binary file into memory
std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    size_t sz = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> b(sz);
    f.read(reinterpret_cast<char*>(b.data()), sz);
    return b;
}

// Generate Ed25519 keypair
bool cmd_keygen(const std::string& key_prefix) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) return false;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    std::string priv_path = key_prefix + "_private.pem";
    std::string pub_path = key_prefix + "_public.pem";

    FILE* fp_priv = fopen(priv_path.c_str(), "wb");
    PEM_write_PrivateKey(fp_priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp_priv);

    FILE* fp_pub = fopen(pub_path.c_str(), "wb");
    PEM_write_PUBKEY(fp_pub, pkey);
    fclose(fp_pub);

    EVP_PKEY_free(pkey);
    std::cout << "[+] Generated Ed25519 keypair:\n"
              << "    Private Key: " << priv_path << "\n"
              << "    Public Key:  " << pub_path << std::endl;
    return true;
}

// Sign and pack .splugin
bool cmd_pack(const std::string& priv_key_path,
              uint32_t tier,
              const std::string& manifest_path,
              const std::string& payload_path,
              const std::string& out_path) {
    auto manifest_data = read_file(manifest_path);
    auto payload_data = read_file(payload_path);

    if (manifest_data.empty() || payload_data.empty()) {
        std::cerr << "[-] Failed to read manifest or payload file." << std::endl;
        return false;
    }

    // Load Ed25519 Private Key
    FILE* fp_key = fopen(priv_key_path.c_str(), "rb");
    if (!fp_key) {
        std::cerr << "[-] Cannot open private key: " << priv_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp_key, nullptr, nullptr, nullptr);
    fclose(fp_key);
    if (!pkey) return false;

    // Digest to sign: SHA256(Manifest) + SHA256(Payload)
    auto h_man = sha256_buffer(manifest_data.data(), manifest_data.size());
    auto h_pay = sha256_buffer(payload_data.data(), payload_data.size());

    std::vector<uint8_t> sign_input;
    sign_input.insert(sign_input.end(), h_man.begin(), h_man.end());
    sign_input.insert(sign_input.end(), h_pay.begin(), h_pay.end());

    SPluginHeader hdr;
    hdr.magic = SPLUGIN_MAGIC;
    hdr.version = SPLUGIN_VERSION;
    hdr.tier = tier;
    hdr.manifest_len = static_cast<uint32_t>(manifest_data.size());
    hdr.payload_len = static_cast<uint64_t>(payload_data.size());

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = sizeof(hdr.signature);
    EVP_DigestSign(md_ctx, hdr.signature, &sig_len, sign_input.data(), sign_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    // Write final .splugin container
    std::ofstream out(out_path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    out.write(reinterpret_cast<const char*>(manifest_data.data()), manifest_data.size());
    out.write(reinterpret_cast<const char*>(payload_data.data()), payload_data.size());
    out.close();

    std::cout << "[+] Successfully packed and signed container: " << out_path << "\n"
              << "    Tier: " << tier << " | Manifest: " << hdr.manifest_len 
              << " bytes | Payload: " << hdr.payload_len << " bytes" << std::endl;
    return true;
}

// Verify an .splugin container
bool cmd_verify(const std::string& pub_key_path, const std::string& splugin_path) {
    auto container = read_file(splugin_path);
    if (container.size() < sizeof(SPluginHeader)) {
        std::cerr << "[-] File too small to be valid .splugin" << std::endl;
        return false;
    }

    SPluginHeader hdr;
    std::memcpy(&hdr, container.data(), sizeof(hdr));

    if (hdr.magic != SPLUGIN_MAGIC) {
        std::cerr << "[-] Invalid magic header bytes!" << std::endl;
        return false;
    }

    size_t expected_sz = sizeof(SPluginHeader) + hdr.manifest_len + hdr.payload_len;
    if (container.size() != expected_sz) {
        std::cerr << "[-] Corrupt container size mismatch!" << std::endl;
        return false;
    }

    const uint8_t* man_ptr = container.data() + sizeof(SPluginHeader);
    const uint8_t* pay_ptr = man_ptr + hdr.manifest_len;

    auto h_man = sha256_buffer(man_ptr, hdr.manifest_len);
    auto h_pay = sha256_buffer(pay_ptr, hdr.payload_len);

    std::vector<uint8_t> sign_input;
    sign_input.insert(sign_input.end(), h_man.begin(), h_man.end());
    sign_input.insert(sign_input.end(), h_pay.begin(), h_pay.end());

    FILE* fp_key = fopen(pub_key_path.c_str(), "rb");
    if (!fp_key) {
        std::cerr << "[-] Cannot open public key: " << pub_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp_key, nullptr, nullptr, nullptr);
    fclose(fp_key);
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    int res = EVP_DigestVerify(md_ctx, hdr.signature, 64, sign_input.data(), sign_input.size());
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (res == 1) {
        std::cout << "[VERIFIED] Signature is AUTHENTIC and tamper-free!\n"
                  << "           Tier: " << hdr.tier << " | Payload size: " 
                  << hdr.payload_len << " bytes" << std::endl;
        return true;
    } else {
        std::cerr << "[REJECTED] Cryptographic signature INVALID or container TAMPERED!" << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  sentinel-plugin-pack keygen <prefix>\n"
                  << "  sentinel-plugin-pack pack <priv_key> <tier: 0=native,1=wasm,2=lua> <manifest> <payload> <out.splugin>\n"
                  << "  sentinel-plugin-pack verify <pub_key> <in.splugin>\n";
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "keygen" && argc >= 3) {
        return cmd_keygen(argv[2]) ? 0 : 1;
    } else if (cmd == "pack" && argc >= 7) {
        uint32_t tier = std::stoul(argv[3]);
        return cmd_pack(argv[2], tier, argv[4], argv[5], argv[6]) ? 0 : 1;
    } else if (cmd == "verify" && argc >= 4) {
        return cmd_verify(argv[2], argv[3]) ? 0 : 1;
    }

    std::cerr << "Invalid arguments." << std::endl;
    return 1;
}