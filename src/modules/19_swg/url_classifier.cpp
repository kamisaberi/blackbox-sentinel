#include "url_classifier.hpp"
#include <algorithm>

namespace sentinel::modules::swg {

URLClassifier::URLClassifier() {
    blocked_tlds_.insert(".top");
    blocked_tlds_.insert(".xyz");
    blocked_tlds_.insert(".onion");
    blocked_tlds_.insert(".cc");
}

bool URLClassifier::is_malicious_url(const std::string& url, std::string& out_category) {
    std::lock_guard<std::mutex> lock(classifier_mutex_);

    // Typosquatting / Homograph Phishing patterns
    if (url.find("login-secure-bank") != std::string::npos ||
        url.find("update-account-verification") != std::string::npos) {
        out_category = "Zero-Minute Credential Phishing Target";
        return true;
    }

    // Direct IP address URL requests in outbound enterprise web browsing
    if (url.find("http://") != std::string::npos) {
        size_t host_start = url.find("http://") + 7;
        size_t host_end = url.find("/", host_start);
        std::string host = url.substr(host_start, host_end - host_start);

        bool is_raw_ip = !host.empty() && std::all_of(host.begin(), host.end(), [](char c){
            return std::isdigit(c) || c == '.';
        });

        if (is_raw_ip) {
            out_category = "Direct IP Egress Web Request (Bypassing DNS)";
            return true;
        }
    }

    for (const auto& tld : blocked_tlds_) {
        if (url.find(tld) != std::string::npos) {
            out_category = "High-Risk Top Level Domain (" + tld + ")";
            return true;
        }
    }

    return false;
}

} // namespace sentinel::modules::swg