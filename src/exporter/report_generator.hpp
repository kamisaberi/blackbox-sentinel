#pragma once
#include <string>

namespace sentinel::exporter {

class ReportGenerator {
public:
    static bool generate_cmmc_compliance_report(const std::string& output_file_path);
};

} // namespace sentinel::exporter