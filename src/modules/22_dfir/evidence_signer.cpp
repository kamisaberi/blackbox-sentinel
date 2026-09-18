#include "evidence_signer.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

namespace sentinel::modules::dfir {

std::string EvidenceSigner::compute_sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) return "";

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buf[4096];
    while (file.read(buf, sizeof(buf))) {
        SHA256_Update(&sha256, buf, file.gcount());
    }
    if (file.gcount() > 0) {
        SHA256_Update(&sha256, buf, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool EvidenceSigner::seal_evidence(const std::string& filepath, const std::string& case_id, std::string& out_receipt) {
    std::string hash = compute_sha256_file(filepath);
    if (hash.empty()) return false;

    out_receipt = "CASE_ID:" + case_id + "|HASH_SHA256:" + hash + "|STATUS:CHAIN_OF_CUSTODY_SEALED";
    return true;
}

} // namespace sentinel::modules::dfir