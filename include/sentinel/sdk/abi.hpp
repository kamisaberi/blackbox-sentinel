#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef SENTINEL_PLUGIN_EXPORTS
        #define ARY_SDK_API __declspec(dllexport)
    #else
        #define ARY_SDK_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4
        #define ARY_SDK_API __attribute__((visibility("default")))
    #else
        #define ARY_SDK_API
    #endif
#endif

#define SENTINEL_SDK_VERSION_MAJOR 1
#define SENTINEL_SDK_VERSION_MINOR 0
#define SENTINEL_SDK_VERSION_PATCH 0
#define SENTINEL_SDK_MAGIC 0x4152594F53444B31ULL // "ARYOSDK1"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SentinelTierType {
    SENTINEL_TIER_NATIVE_CPP = 0,
    SENTINEL_TIER_WASM       = 1,
    SENTINEL_TIER_LUA        = 2
} SentinelTierType;

typedef enum SentinelActionVerdict {
    SENTINEL_VERDICT_PASS           = 0,
    SENTINEL_VERDICT_INSPECT_DEEP   = 1,
    SENTINEL_VERDICT_ALERT          = 2,
    SENTINEL_VERDICT_KERNEL_DROP    = 3,
    SENTINEL_VERDICT_HONEYPOT_DIVERT= 4
} SentinelActionVerdict;

typedef struct SentinelDissectorResult {
    SentinelActionVerdict verdict;
    uint32_t              threat_score;    // Scaled 0 - 1000 (0.0 to 1.0)
    uint32_t              rule_id;         // Unique rule ID or 0 if clean
    uint64_t              semantic_tags;   // Bitmask of tags (see semantic_tags.hpp)
    char                  threat_name[64]; // Null-terminated canonical name
} SentinelDissectorResult;

typedef struct SentinelRawPacket {
    const uint8_t* data;
    size_t         length;
    uint64_t       timestamp_ns;
    uint32_t       ingress_ifindex;
    uint16_t       network_proto;   // e.g. 0x0800 IPv4, 0x86DD IPv6, 0x88B8 GOOSE
    uint8_t        transport_proto; // 6 (TCP), 17 (UDP), etc.
    uint8_t        reserved;
} SentinelRawPacket;

// Host callback function pointers supplied by Sentinel engine to plugins
typedef struct SentinelHostInterface {
    uint64_t engine_version;
    void (*log_message)(int level, const char* sender, const char* msg);
    int  (*request_ebpf_drop_ip)(uint32_t ipv4, uint32_t duration_sec);
    int  (*request_ebpf_drop_ip6)(const uint8_t ipv6[16], uint32_t duration_sec);
    void (*emit_metric_counter)(const char* metric_name, uint64_t delta);
    uint64_t (*get_monotonic_time_ns)(void);
} SentinelHostInterface;

// Function pointer signatures exported by the plugin
typedef int (*SentinelPluginInitFn)(const SentinelHostInterface* host_iface);
typedef void (*SentinelPluginShutdownFn)(void);
typedef SentinelDissectorResult (*SentinelDissectFn)(const SentinelRawPacket* packet);

typedef struct SentinelPluginDescriptor {
    uint64_t                 magic;              // Must match SENTINEL_SDK_MAGIC
    uint32_t                 sdk_version_major;
    uint32_t                 sdk_version_minor;
    SentinelTierType         tier;
    const char*              plugin_id;          // Unique string: "org.aryorithm.modbus_guard"
    const char*              plugin_name;        // Display name
    const char*              plugin_version;     // Semver string: "1.0.0"
    const char*              target_protocol;    // e.g. "MODBUS", "DNP3", "S7COMM"
    uint16_t                 default_port;       // e.g. 502, 20000, 102
    uint16_t                 reserved;
    SentinelPluginInitFn     init_fn;
    SentinelPluginShutdownFn shutdown_fn;
    SentinelDissectFn        dissect_fn;
} SentinelPluginDescriptor;

#ifdef __cplusplus
}
#endif