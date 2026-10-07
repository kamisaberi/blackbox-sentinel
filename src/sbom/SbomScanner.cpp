#include "SbomScanner.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <openssl/sha.h>

namespace sentinel::sbom {

std::string SbomScanner::calculate_file_sha256(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    char buf[32768];
    while (f.read(buf, sizeof(buf))) {
        SHA256_Update(&ctx, buf, f.gcount());
    }
    if (f.gcount() > 0) {
        SHA256_Update(&ctx, buf, f.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void SbomScanner::scan_dynamic_libraries(std::vector<ComponentEntry>& out_comps) {
    std::vector<std::string> search_dirs = {
        "/usr/local/lib",
        "/usr/local/lib/xinfer/plugins",
        "/usr/local/lib/sentinel/plugins"
    };

    for (const auto& dir : search_dirs) {
        if (!std::filesystem::exists(dir)) continue;

        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".so") {
                std::string fname = entry.path().filename().string();
                std::string hash = calculate_file_sha256(entry.path().string());

                out_comps.push_back({
                    .name = fname,
                    .version = "1.0.0",
                    .type = "library",
                    .sha256_hash = hash,
                    .filesystem_path = entry.path().string()
                });
            }
        }
    }
}

void SbomScanner::scan_kernel_modules(std::vector<ComponentEntry>& out_comps) {
    std::ifstream mod_file("/proc/modules");
    if (!mod_file.is_open()) return;

    std::string line;
    while (std::getline(mod_file, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string mod_name;
        iss >> mod_name;

        if (!mod_name.empty()) {
            out_comps.push_back({
                .name = "kernel-mod-" + mod_name,
                .version = "in-tree",
                .type = "driver",
                .sha256_hash = "kernel-resident",
                .filesystem_path = "/lib/modules"
            });
        }
    }
}

SbomManifest SbomScanner::scan_local_appliance() {
    SbomManifest manifest;
    manifest.generated_at_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    
    manifest.serial_number = "urn:uuid:aryorithm-sbom-" + std::to_string(manifest.generated_at_sec);

    // 1. Core Operating System
    manifest.components.push_back({
        .name = "Linux Kernel",
        .version = "6.8-generic",
        .type = "operating-system",
        .sha256_hash = "native-host-kernel",
        .filesystem_path = "/boot"
    });

    // 2. Binary Engines
    manifest.components.push_back({
        .name = "blackbox-sentinel-daemon",
        .version = "1.0.0",
        .type = "application",
        .sha256_hash = calculate_file_sha256("/usr/local/bin/sentinel"),
        .filesystem_path = "/usr/local/bin/sentinel"
    });

    // 3. Scan shared objects and drivers
    scan_dynamic_libraries(manifest.components);
    scan_kernel_modules(manifest.components);

    return manifest;
}

std::string SbomScanner::generate_cyclonedx_json() {
    SbomManifest mf = scan_local_appliance();

    std::ostringstream ss;
    ss << "{\n"
       << "  \"bomFormat\": \"" << mf.bom_format << "\",\n"
       << "  \"specVersion\": \"" << mf.spec_version << "\",\n"
       << "  \"serialNumber\": \"" << mf.serial_number << "\",\n"
       << "  \"version\": 1,\n"
       << "  \"metadata\": {\n"
       << "    \"timestamp\": " << mf.generated_at_sec << ",\n"
       << "    \"component\": {\n"
       << "      \"name\": \"Blackbox Sentinel Cyber-Physical Appliance\",\n"
       << "      \"version\": \"1.0.0\",\n"
       << "      \"type\": \"device\"\n"
       << "    }\n"
       << "  },\n"
       << "  \"components\": [\n";

    for (size_t i = 0; i < mf.components.size(); ++i) {
        const auto& c = mf.components[i];
        ss << "    {\n"
           << "      \"name\": \"" << c.name << "\",\n"
           << "      \"version\": \"" << c.version << "\",\n"
           << "      \"type\": \"" << c.type << "\",\n"
           << "      \"hashes\": [\n"
           << "        {\n"
           << "          \"alg\": \"SHA-256\",\n"
           << "          \"content\": \"" << c.sha256_hash << "\"\n"
           << "        }\n"
           << "      ],\n"
           << "      \"properties\": [\n"
           << "        {\"name\": \"path\", \"value\": \"" << c.filesystem_path << "\"}\n"
           << "      ]\n"
           << "    }" << (i + 1 < mf.components.size() ? ",\n" : "\n");
    }

    ss << "  ]\n}";
    return ss.str();
}

bool SbomScanner::export_manifest(const std::string& output_path) {
    std::string json = generate_cyclonedx_json();
    std::filesystem::create_directories(std::filesystem::path(output_path).parent_path());

    std::ofstream out(output_path);
    if (!out.is_open()) return false;
    out << json;
    out.close();
    return true;
}

} // namespace sentinel::sbom