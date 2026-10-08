#ifndef SENTINEL_SDK_HOST_API_H
#define SENTINEL_SDK_HOST_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Log levels
#define SENTINEL_LOG_DEBUG 0
#define SENTINEL_LOG_INFO  1
#define SENTINEL_LOG_WARN  2
#define SENTINEL_LOG_ERROR 3

// Host system calls callable from extensions
void     sentinel_host_log(int level, const char* sender, const char* message);
int      sentinel_host_drop_ipv4(uint32_t ipv4, uint32_t duration_seconds);
int      sentinel_host_drop_ipv6(const uint8_t ipv6[16], uint32_t duration_seconds);
void     sentinel_host_emit_metric(const char* metric_name, uint64_t delta);
uint64_t sentinel_host_monotonic_ns(void);

#ifdef __cplusplus
}
#endif

#endif // SENTINEL_SDK_HOST_API_H