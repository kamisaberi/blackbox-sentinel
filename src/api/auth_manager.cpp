#include "auth_manager.hpp"
#include <iostream>

namespace sentinel::api {

AuthManager::AuthManager() {
    // Default admin user session
    UserSession admin_session{"admin", UserRole::Admin, "valid_sentinel_token_12345"};
    active_sessions_["valid_sentinel_token_12345"] = admin_session;
}

std::string AuthManager::authenticate_user(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (username == "admin" && password == "admin123") {
        std::string token = "jwt_token_" + std::to_string(std::hash<std::string>{}(username));
        active_sessions_[token] = {username, UserRole::Admin, token};
        return token;
    }
    return "";
}

bool AuthManager::validate_token(const std::string& token, UserRole required_role) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    auto it = active_sessions_.find(token);
    if (it != active_sessions_.end()) {
        // Admin has access to all roles
        if (it->second.role == UserRole::Admin) return true;
        return (it->second.role == required_role);
    }
    return false;
}

} // namespace sentinel::api