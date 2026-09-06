#pragma once

#include <string>
#include <unordered_set>
#include <mutex>

namespace sentinel::modules::swg {

class URLClassifier {
public:
    URLClassifier();
    ~URLClassifier() = default;

    bool is_malicious_url(const std::string& url_or_domain, std::string& out_category);

private:
    std::unordered_set<std::string> blocked_tlds_;
    std::mutex classifier_mutex_;
};

} // namespace sentinel::modules::swg