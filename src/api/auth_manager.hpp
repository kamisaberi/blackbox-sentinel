#pragma once
#include <string>
#include <unordered_map>
#include <mutex>

namespace sentinel::api {

enum class UserRole {
    Admin,
    Analyst,
    Auditor
};

struct UserSession {
    std::string username;
    UserRole role;
    std::string token;
};

class AuthManager {
public:
    AuthManager();
    ~AuthManager() = default;

    std::string authenticate_user(const std::string& username, const std::string& password);
    bool validate_token(const std::string& token, UserRole required_role);

private:
    std::unordered_map<std::string, UserSession> active_sessions_;
    std::mutex auth_mutex_;
};

} // namespace sentinel::api