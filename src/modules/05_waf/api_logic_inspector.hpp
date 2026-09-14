#pragma once

#include <string>

namespace sentinel::modules::waf {

class APILogicInspector {
public:
    APILogicInspector() = default;
    ~APILogicInspector() = default;

    bool detect_path_traversal(const std::string& path);
    bool detect_bola_idor(const std::string& path, const std::string& auth_token);
};

} // namespace sentinel::modules::waf