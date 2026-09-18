#pragma once

#include <string>

namespace sentinel::modules::dfir {

class EvidenceSigner {
public:
    EvidenceSigner() = default;
    ~EvidenceSigner() = default;

    std::string compute_sha256_file(const std::string& filepath);
    bool seal_evidence(const std::string& filepath, const std::string& case_id, std::string& out_receipt);
};

} // namespace sentinel::modules::dfir