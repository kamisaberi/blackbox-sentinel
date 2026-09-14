#include "api_logic_inspector.hpp"

namespace sentinel::modules::waf {

bool APILogicInspector::detect_path_traversal(const std::string& path) {
    if (path.find("../") != std::string::npos ||
        path.find("..\\") != std::string::npos ||
        path.find("%2e%2e%2f") != std::string::npos ||
        path.find("%2e%2e/") != std::string::npos) {
        return true;
    }
    return false;
}

bool APILogicInspector::detect_bola_idor(const std::string& path, const std::string& auth_token) {
    // Check for resource traversal without valid authorization token
    if (path.find("/api/v1/users/") != std::string::npos ||
        path.find("/api/v1/accounts/") != std::string::npos) {
        if (auth_token.empty() || auth_token == "Bearer null") {
            return true; // Unauthorized Broken Object Level Access
        }
    }
    return false;
}

} // namespace sentinel::modules::waf