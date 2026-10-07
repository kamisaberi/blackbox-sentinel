#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace sentinel::sbom {

struct ComponentEntry {
    std::string name;
    std::string version;
    std::string type; // "library", "operating-system", "application", "driver"
    std::string sha256_hash;
    std::string filesystem_path;
};

struct SbomManifest {
    std::string bom_format{"CycloneDX"};
    std::string spec_version{"1.5"};
    std::string serial_number;
    uint64_t generated_at_sec;
    std::vector<ComponentEntry> components;
};

class SbomScanner {
public:
    static SbomScanner& instance() {
        static SbomScanner inst;
        return inst;
    }

    // Scans local Linux rootfs, libraries, and kernel drivers
    SbomManifest scan_local_appliance();

    // Serializes inventory to CycloneDX JSON format
    std::string generate_cyclonedx_json();

    // Exports manifest to target path (/etc/sentinel/sbom.json)
    bool export_manifest(const std::string& output_path = "/etc/sentinel/sbom.json");

private:
    SbomScanner() = default;

    static std::string calculate_file_sha256(const std::string& path);
    void scan_dynamic_libraries(std::vector<ComponentEntry>& out_comps);
    void scan_kernel_modules(std::vector<ComponentEntry>& out_comps);
};

} // namespace sentinel::sbom