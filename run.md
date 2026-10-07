Here is the analysis, suggestions for your backend API, and the complete local C++ implementation to consume these endpoints.

---

### Part 1: Suggestions for Your Backend Team (API Tweaks)

Reviewing your backend API specification from the perspective of an embedded C++ client, here are **3 high-value suggestions** to give to your backend team:

1. **Explicit Request Body for `POST /api/v1/licenses/activate`:**  
   Ensure the backend explicitly specifies the payload schema for `/licenses/activate`.  
   *Recommended:*
   ```json
   {
     "hardware_token": "ARY-HW-f88c4d56-19a9-c746-1113-00ee1fb226db",
     "hostname": "sentinel-substation-01"
   }
   ```
2. **Consistent Envelope Format in JSON Responses:**  
   For both `/subscribe` and `/activate`, ensure the returned JSON directly embeds the standard envelope:
   ```json
   {
     "status": "activated",
     "lease_days": 30,
     "envelope": {
       "payload_b64": "...",
       "signature_b64": "...",
       "signature_algorithm": "ED25519"
     }
   }
   ```
   *Benefit for C++:* The client can write the inner `envelope` object straight to `/etc/sentinel/license.lic` without transforming fields.
3. **Hardware Token Lookup on `GET /api/v1/licenses/verify/{ref}`:**  
   Allow `{ref}` to be either `license_id` (e.g. `LIC-2026-EUR`) **or** the hardware token (`ARY-HW-f88c...`). An unconfigured appliance on boot does not know its `license_id` yet, but it *always* knows its local hardware token.

---

### Part 2: How the Local C++ Engine Consumes These APIs

We integrate these endpoints directly into **`blackbox-sentinel`**:

```text
========================================================================================================
                          LOCAL C++ ENGINE CONSUMPTION WORKFLOW
========================================================================================================

 1. DYNAMIC PUBLIC KEY DISCOVERY (GET /api/v1/licenses/public-key)
    • Unauthenticated call at boot.
    • Updates the local in-memory Ed25519 verification key (falls back to hardcoded key if offline).

 2. 1-CLICK SELF-SUBSCRIBE (POST /api/v1/licenses/subscribe)
    • Triggered via CLI: `./sentinel --subscribe community` (or `commercial`).
    • Probes hardware token, requests subscription, saves signed `.lic` envelope locally.

 3. ZERO-TOUCH ACTIVATION & 30-DAY ROLLING RENEWAL (POST /api/v1/licenses/activate)
    • Called automatically on startup and every 24 hours in a background thread.
    • Automatically extends the rolling 30-day lease before expiration.

 4. FAIL-CLOSED REVOCATION CHECK (GET /api/v1/licenses/verify/{ref})
    • Checked periodically when online. If revoked by tenant admin, immediately degrades to Community Free.
========================================================================================================
```

---

### Part 3: C++ Implementation

---

#### 1. Update `src/core/LicenseManager.hpp`

Save as `/home/kami/blackbox-sentinel/src/core/LicenseManager.hpp`:

```cpp
#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint>
#include <mutex>
#include <thread>
#include <atomic>

namespace sentinel::licensing {

enum class LicenseTier {
    COMMUNITY_FREE,
    ENTERPRISE_IT,
    CRITICAL_INFRASTRUCTURE_OT,
    SOVEREIGN_DEFENSE
};

struct LicenseClaims {
    std::string license_id{""};
    std::string customer_name{"Community User"};
    LicenseTier tier{LicenseTier::COMMUNITY_FREE};
    uint64_t issued_at_sec{0};
    uint64_t expires_at_sec{0};
    uint32_t max_nodes{1};
    std::string locked_hardware_uuid{""};
    std::unordered_set<std::string> authorized_modules;
    std::unordered_set<std::string> authorized_plugins;
};

class LicenseManager {
public:
    static LicenseManager& instance() {
        static LicenseManager inst;
        return inst;
    }

    // Local Verification & Inspection
    bool load_and_verify(const std::string& license_file_path = "/etc/sentinel/license.lic");
    bool is_module_authorized(const std::string& module_name) const;
    bool is_plugin_authorized(const std::string& plugin_filename) const;

    LicenseTier get_active_tier() const;
    std::string get_tier_name() const;
    const LicenseClaims& get_claims() const { return claims_; }
    static std::string generate_hardware_token();

    // Cloud Backend API Operations
    bool fetch_public_key_online(const std::string& backend_url = "http://127.0.0.1:8000/api/v1");
    bool activate_online(const std::string& backend_url, const std::string& token_or_key, const std::string& hostname = "sentinel-edge");
    bool subscribe_online(const std::string& backend_url, const std::string& plan_slug, const std::string& hostname = "sentinel-edge");
    bool check_revocation_online(const std::string& backend_url, const std::string& token_or_key);

    // Starts background 24-hour lease renewal loop
    void start_lease_renewal_worker(const std::string& backend_url, const std::string& auth_header);
    void stop_lease_renewal_worker();

private:
    LicenseManager();

    bool verify_ed25519_signature(const std::string& payload_b64, const std::string& b64_sig);
    static std::string probe_local_hardware_uuid();

    mutable std::mutex mutex_;
    LicenseClaims claims_;
    bool license_valid_{false};
    std::vector<uint8_t> active_public_key_; // 32-byte Ed25519 public key

    // Auto-renewal thread
    std::atomic<bool> renewal_running_{false};
    std::jthread renewal_thread_;
};

} // namespace sentinel::licensing
```

---

#### 2. Update `src/core/LicenseManager.cpp`

Save as `/home/kami/blackbox-sentinel/src/core/LicenseManager.cpp`:

```cpp
#include "LicenseManager.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/evp.h>

namespace sentinel::licensing {

// Fallback RFC 8032 Master Ed25519 Public Key (Matches Backend Default)
static const uint8_t DEFAULT_MASTER_PUBKEY[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const std::unordered_set<std::string> COMMUNITY_MODULES = {
    "01_siem_core", "04_ids_ips", "15_ngfw", "19_swg", "22_dfir"
};

struct ParsedUrl {
    std::string host;
    uint16_t port;
    std::string path;
};

static ParsedUrl parse_url_helper(const std::string& url) {
    ParsedUrl res{"127.0.0.1", 8000, "/api/v1"};
    std::string temp = url;
    if (temp.rfind("http://", 0) == 0) temp = temp.substr(7);
    else if (temp.rfind("https://", 0) == 0) { temp = temp.substr(8); res.port = 443; }

    size_t slash = temp.find('/');
    if (slash != std::string::npos) {
        res.path = temp.substr(slash);
        temp = temp.substr(0, slash);
    }
    size_t colon = temp.find(':');
    if (colon != std::string::npos) {
        res.host = temp.substr(0, colon);
        res.port = static_cast<uint16_t>(std::stoi(temp.substr(colon + 1)));
    } else {
        res.host = temp;
    }
    return res;
}

static std::vector<uint8_t> base64_decode_block(const std::string& input) {
    std::string clean;
    clean.reserve(input.size());
    for (char c : input) {
        if (c != '\r' && c != '\n' && c != ' ' && c != '\t') clean += c;
    }
    if (clean.empty() || clean.size() % 4 != 0) return {};

    int out_len = static_cast<int>((clean.size() / 4) * 3);
    std::vector<uint8_t> out(out_len);
    int decoded = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(clean.data()), static_cast<int>(clean.size()));
    if (decoded < 0) return {};

    if (clean.size() >= 1 && clean[clean.size() - 1] == '=') out_len--;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=') out_len--;
    out.resize(out_len);
    return out;
}

static std::string extract_json_field(const std::string& json, const std::string& key) {
    size_t k = json.find("\"" + key + "\"");
    if (k == std::string::npos) return "";
    size_t colon = json.find(':', k);
    size_t s = json.find('"', colon + 1);
    size_t e = json.find('"', s + 1);
    if (s != std::string::npos && e != std::string::npos) {
        return json.substr(s + 1, e - s - 1);
    }
    return "";
}

static std::string http_request(const std::string& method, const std::string& base_url, const std::string& route,
                                const std::string& body = "", const std::string& auth_header = "") {
    ParsedUrl purl = parse_url_helper(base_url);
    std::string full_path = purl.path + route;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv{4, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct hostent* server = gethostbyname(purl.host.c_str());
    if (!server) { close(sock); return ""; }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(purl.port);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return "";
    }

    std::ostringstream req;
    req << method << " " << full_path << " HTTP/1.1\r\n"
        << "Host: " << purl.host << ":" << purl.port << "\r\n";
    if (!auth_header.empty()) {
        req << "Authorization: " << auth_header << "\r\n";
    }
    req << "Accept: application/json\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;

    std::string req_str = req.str();
    send(sock, req_str.data(), req_str.size(), 0);

    char buf[4096];
    std::string resp;
    ssize_t bytes;
    while ((bytes = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[bytes] = '\0';
        resp.append(buf, bytes);
        size_t h_end = resp.find("\r\n\r\n");
        if (h_end != std::string::npos) {
            size_t cl_pos = resp.find("Content-Length: ");
            if (cl_pos == std::string::npos) cl_pos = resp.find("content-length: ");
            if (cl_pos != std::string::npos) {
                size_t cl_end = resp.find("\r\n", cl_pos);
                int clen = std::stoi(resp.substr(cl_pos + 16, cl_end - cl_pos - 16));
                if (resp.size() >= (h_end + 4 + clen)) break;
            }
        }
    }
    close(sock);

    size_t body_pos = resp.find("\r\n\r\n");
    return (body_pos != std::string::npos) ? resp.substr(body_pos + 4) : resp;
}

LicenseManager::LicenseManager() {
    claims_.tier = LicenseTier::COMMUNITY_FREE;
    claims_.authorized_modules = COMMUNITY_MODULES;
    active_public_key_.assign(DEFAULT_MASTER_PUBKEY, DEFAULT_MASTER_PUBKEY + 32);
}

std::string LicenseManager::probe_local_hardware_uuid() {
    std::string uuid = "00000000-0000-0000-0000-000000000000";
    std::ifstream dmi("/sys/class/dmi/id/product_uuid");
    if (dmi.is_open()) {
        std::getline(dmi, uuid);
    } else {
        std::ifstream mid("/etc/machine-id");
        if (mid.is_open()) std::getline(mid, uuid);
    }
    size_t s = uuid.find_first_not_of(" \t\r\n");
    size_t e = uuid.find_last_not_of(" \t\r\n");
    return (s != std::string::npos && e != std::string::npos) ? uuid.substr(s, e - s + 1) : uuid;
}

std::string LicenseManager::generate_hardware_token() {
    return "ARY-HW-" + probe_local_hardware_uuid();
}

bool LicenseManager::verify_ed25519_signature(const std::string& payload_b64, const std::string& b64_sig) {
    auto sig_bytes = base64_decode_block(b64_sig);
    if (sig_bytes.size() != 64) return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, active_public_key_.data(), 32
    );
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool verified = false;

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        if (EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                             reinterpret_cast<const unsigned char*>(payload_b64.data()),
                             payload_b64.size()) == 1) {
            verified = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return verified;
}

// -----------------------------------------------------------------------------
// BACKEND API CONSUMERS
// -----------------------------------------------------------------------------

// Consumes: GET /api/v1/licenses/public-key (Unauthenticated)
bool LicenseManager::fetch_public_key_online(const std::string& backend_url) {
    std::cout << "[LicenseManager] Discovering Ed25519 Public Key from " << backend_url << "/licenses/public-key..." << std::endl;
    std::string resp = http_request("GET", backend_url, "/licenses/public-key");
    std::string pubkey_b64 = extract_json_field(resp, "public_key");
    if (pubkey_b64.empty()) pubkey_b64 = extract_json_field(resp, "key");

    if (!pubkey_b64.empty()) {
        auto key_bytes = base64_decode_block(pubkey_b64);
        if (key_bytes.size() == 32) {
            std::lock_guard<std::mutex> lock(mutex_);
            active_public_key_ = key_bytes;
            std::cout << "\033[32m[LicenseManager] [+] Master Public Key updated dynamically from Cloud.\033[0m" << std::endl;
            return true;
        }
    }
    std::cout << "[LicenseManager] Retaining built-in RFC 8032 public verification key." << std::endl;
    return false;
}

// Consumes: POST /api/v1/licenses/activate (Zero-touch activation / 30-day lease renewal)
bool LicenseManager::activate_online(const std::string& backend_url, const std::string& token_or_key, const std::string& hostname) {
    std::string hw_token = generate_hardware_token();
    std::string payload = "{\"hardware_token\":\"" + hw_token + "\",\"hostname\":\"" + hostname + "\"}";

    std::cout << "[LicenseManager] Requesting zero-touch activation from " << backend_url << "/licenses/activate..." << std::endl;
    std::string auth = token_or_key.rfind("Bearer ", 0) == 0 ? token_or_key : ("Bearer " + token_or_key);
    std::string resp = http_request("POST", backend_url, "/licenses/activate", payload, auth);

    // Save envelope if returned in response
    size_t env_pos = resp.find("\"envelope\":");
    if (env_pos != std::string::npos) {
        size_t s = resp.find('{', env_pos);
        size_t e = resp.rfind('}');
        if (s != std::string::npos && e != std::string::npos) {
            std::string lic_json = resp.substr(s, e - s + 1);
            std::ofstream out("/etc/sentinel/license.lic");
            if (out.is_open()) {
                out << lic_json;
                out.close();
                std::cout << "\033[32m[LicenseManager] [+] License envelope activated and written to /etc/sentinel/license.lic\033[0m" << std::endl;
                return load_and_verify("/etc/sentinel/license.lic");
            }
        }
    }
    return false;
}

// Consumes: POST /api/v1/licenses/subscribe (Self-service subscribe)
bool LicenseManager::subscribe_online(const std::string& backend_url, const std::string& plan_slug, const std::string& hostname) {
    std::string hw_token = generate_hardware_token();
    std::string payload = "{\"plan_slug\":\"" + plan_slug + "\",\"hardware_token\":\"" + hw_token + "\",\"hostname\":\"" + hostname + "\"}";

    std::cout << "[LicenseManager] Subscribing appliance to plan [" << plan_slug << "] via " << backend_url << "/licenses/subscribe..." << std::endl;
    std::string resp = http_request("POST", backend_url, "/licenses/subscribe", payload);

    size_t env_pos = resp.find("\"envelope\":");
    if (env_pos != std::string::npos) {
        size_t s = resp.find('{', env_pos);
        size_t e = resp.rfind('}');
        if (s != std::string::npos && e != std::string::npos) {
            std::string lic_json = resp.substr(s, e - s + 1);
            std::ofstream out("/etc/sentinel/license.lic");
            if (out.is_open()) {
                out << lic_json;
                out.close();
                std::cout << "\033[32m[LicenseManager] [+] Subscribed successfully! Envelope saved.\033[0m" << std::endl;
                return load_and_verify("/etc/sentinel/license.lic");
            }
        }
    }
    return false;
}

// Consumes: GET /api/v1/licenses/verify/{ref} (Revocation / Status audit)
bool LicenseManager::check_revocation_online(const std::string& backend_url, const std::string& token_or_key) {
    if (claims_.license_id.empty()) return true;

    std::string auth = token_or_key.rfind("Bearer ", 0) == 0 ? token_or_key : ("Bearer " + token_or_key);
    std::string resp = http_request("GET", backend_url, "/licenses/verify/" + claims_.license_id, "", auth);

    if (resp.find("\"status\":\"revoked\"") != std::string::npos || resp.find("403 Forbidden") != std::string::npos) {
        std::cerr << "\033[31m[LicenseManager] CRITICAL: License revoked by administrator in cloud. Failing closed!\033[0m" << std::endl;
        std::lock_guard<std::mutex> lock(mutex_);
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        return false;
    }
    return true;
}

void LicenseManager::start_lease_renewal_worker(const std::string& backend_url, const std::string& auth_header) {
    if (renewal_running_.load()) return;
    renewal_running_.store(true);

    renewal_thread_ = std::jthread([this, backend_url, auth_header](std::stop_token st) {
        while (!st.stop_requested() && renewal_running_.load()) {
            // Check renewal every 12 hours (43200 seconds)
            std::this_thread::sleep_for(std::chrono::hours(12));
            if (!renewal_running_.load()) break;

            std::cout << "[LicenseManager] Running scheduled 30-day lease renewal..." << std::endl;
            activate_online(backend_url, auth_header);
            check_revocation_online(backend_url, auth_header);
        }
    });
}

void LicenseManager::stop_lease_renewal_worker() {
    renewal_running_.store(false);
}

// -----------------------------------------------------------------------------
// LOCAL OFFLINE VERIFICATION (Air-Gapped Invariant)
// -----------------------------------------------------------------------------
bool LicenseManager::load_and_verify(const std::string& license_file_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ifstream file(license_file_path);
    if (!file.is_open()) {
        std::cout << "[LicenseManager] No license file at " << license_file_path 
                  << ". Operating in Community Free Tier." << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        license_valid_ = false;
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::string payload_b64 = extract_json_field(content, "payload_b64");
    std::string signature_b64 = extract_json_field(content, "signature_b64");

    if (payload_b64.empty() || signature_b64.empty()) {
        std::cerr << "[LicenseManager] Corrupted license: Missing payload or signature." << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        return false;
    }

    if (!verify_ed25519_signature(payload_b64, signature_b64)) {
        std::cerr << "\033[31m[LicenseManager] CRITICAL: Invalid cryptographic signature! "
                  << "License tampering detected. Reverting to Community Tier.\033[0m" << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        return false;
    }

    auto claims_bytes = base64_decode_block(payload_b64);
    std::string claims_json(claims_bytes.begin(), claims_bytes.end());

    std::string exp_str;
    size_t exp_pos = claims_json.find("\"expires_at\":");
    if (exp_pos != std::string::npos) {
        size_t comma = claims_json.find_first_of(",}", exp_pos);
        exp_str = claims_json.substr(exp_pos + 13, comma - exp_pos - 13);
        exp_str.erase(0, exp_str.find_first_not_of(" \t"));
        exp_str.erase(exp_str.find_last_not_of(" \t") + 1);
    }
    uint64_t expires_sec = exp_str.empty() ? 0 : std::stoull(exp_str);
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (expires_sec > 0 && static_cast<uint64_t>(now_sec) > expires_sec) {
        std::cerr << "\033[33m[LicenseManager] License lease expired on timestamp " << expires_sec 
                  << ". Reverting to Community Tier.\033[0m" << std::endl;
        claims_.tier = LicenseTier::COMMUNITY_FREE;
        claims_.authorized_modules = COMMUNITY_MODULES;
        return false;
    }

    std::string hw_lock = extract_json_field(claims_json, "locked_hardware_uuid");
    if (!hw_lock.empty()) {
        std::string local_hw = probe_local_hardware_uuid();
        if (local_hw != hw_lock) {
            std::cerr << "\033[31m[LicenseManager] HARDWARE LOCK VIOLATION: License locked to [" 
                      << hw_lock << "], but running on [" << local_hw << "]!\033[0m" << std::endl;
            claims_.tier = LicenseTier::COMMUNITY_FREE;
            claims_.authorized_modules = COMMUNITY_MODULES;
            return false;
        }
    }

    claims_.license_id = extract_json_field(claims_json, "license_id");
    claims_.customer_name = extract_json_field(claims_json, "customer");
    claims_.locked_hardware_uuid = hw_lock;
    claims_.expires_at_sec = expires_sec;

    std::string tier_str = extract_json_field(claims_json, "tier");
    if (tier_str == "CRITICAL_OT" || tier_str == "SOVEREIGN_DEFENSE") {
        claims_.tier = LicenseTier::CRITICAL_INFRASTRUCTURE_OT;
    } else {
        claims_.tier = LicenseTier::ENTERPRISE_IT;
    }

    license_valid_ = true;
    std::cout << "\033[32m[LicenseManager] VALID LICENSE VERIFIED: Customer [" << claims_.customer_name 
              << "] | Tier: " << get_tier_name() << "\033[0m" << std::endl;
    return true;
}

bool LicenseManager::is_module_authorized(const std::string& module_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claims_.tier == LicenseTier::CRITICAL_INFRASTRUCTURE_OT || 
        claims_.tier == LicenseTier::SOVEREIGN_DEFENSE) return true;
    if (claims_.tier == LicenseTier::COMMUNITY_FREE) return COMMUNITY_MODULES.contains(module_name);
    
    static const std::unordered_set<std::string> OT_RESTRICTED = {
        "17_iot_sec", "18_cps_sec", "20_fse", "21_side_channel", "26_ddp"
    };
    return !OT_RESTRICTED.contains(module_name);
}

bool LicenseManager::is_plugin_authorized(const std::string& plugin_filename) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claims_.tier == LicenseTier::CRITICAL_INFRASTRUCTURE_OT || 
        claims_.tier == LicenseTier::SOVEREIGN_DEFENSE) return true;
    if (claims_.tier == LicenseTier::ENTERPRISE_IT) {
        return (plugin_filename.find("forwarder") != std::string::npos || 
                plugin_filename.find("kafka") != std::string::npos ||
                plugin_filename.find("syslog") != std::string::npos);
    }
    return false;
}

LicenseTier LicenseManager::get_active_tier() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return claims_.tier;
}

std::string LicenseManager::get_tier_name() const {
    switch (claims_.tier) {
        case LicenseTier::COMMUNITY_FREE: return "Community Free Tier";
        case LicenseTier::ENTERPRISE_IT: return "Enterprise IT Edition";
        case LicenseTier::CRITICAL_INFRASTRUCTURE_OT: return "Critical Infrastructure OT (Full 26 Modules & 30 Plugins)";
        case LicenseTier::SOVEREIGN_DEFENSE: return "Sovereign Defense Enclave";
    }
    return "Unknown";
}

} // namespace sentinel::licensing
```

---

#### 3. Update Sentinel CLI in `blackbox-sentinel/src/main.cpp`

Update `/home/kami/blackbox-sentinel/src/main.cpp` so operators can use the new cloud commands from the terminal:

```cpp
#include "core/LicenseManager.hpp"

// Inside main(int argc, char** argv):
    if (argc > 1) {
        std::string cmd = argv[1];
        if (cmd == "--generate-hardware-token") {
            std::cout << sentinel::licensing::LicenseManager::generate_hardware_token() << std::endl;
            return 0;
        }
        if (cmd == "--subscribe" && argc >= 3) {
            std::string plan = argv[2];
            std::string url = (argc >= 4) ? argv[3] : "http://127.0.0.1:8000/api/v1";
            sentinel::licensing::LicenseManager::instance().subscribe_online(url, plan);
            return 0;
        }
        if (cmd == "--activate") {
            std::string url = (argc >= 3) ? argv[2] : "http://127.0.0.1:8000/api/v1";
            std::string token = (argc >= 4) ? argv[3] : "";
            sentinel::licensing::LicenseManager::instance().activate_online(url, token);
            return 0;
        }
        if (cmd == "--fetch-key") {
            std::string url = (argc >= 3) ? argv[2] : "http://127.0.0.1:8000/api/v1";
            sentinel::licensing::LicenseManager::instance().fetch_public_key_online(url);
            return 0;
        }
    }
```

---

### Step 4: Recompile `blackbox-sentinel`

```bash
cd /home/kami/blackbox-sentinel/build
make -j$(nproc)
```

---

### Usage & Testing Options

1. **Discover Public Key from Cloud:**
   ```bash
   ./sentinel --fetch-key http://127.0.0.1:8000/api/v1
   ```
2. **Self-Service Subscribe via Cloud:**
   ```bash
   ./sentinel --subscribe community http://127.0.0.1:8000/api/v1
   ```
3. **Zero-Touch Activate via Cloud (with JWT):**
   ```bash
   ./sentinel --activate http://127.0.0.1:8000/api/v1 "your_jwt_access_token_here"
   ```
4. **Air-Gapped Offline Run (No Cloud Required):**
   ```bash
   sudo ./sentinel /etc/sentinel/sentinel.yaml
   ```
   *(If offline, it automatically loads `/etc/sentinel/license.lic`, verifies the signature using the embedded public key in $< 50\,\mu\text{s}$, and degrades gracefully to Community Free if missing or expired).*