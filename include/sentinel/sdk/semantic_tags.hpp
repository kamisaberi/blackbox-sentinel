#pragma once

#include <cstdint>

namespace sentinel::sdk::tags {

inline constexpr uint64_t NONE                       = 0ULL;
inline constexpr uint64_t CPS_ACTUATOR_WRITE         = 1ULL << 0;  // Coil/Holding Register modification
inline constexpr uint64_t CPS_PLC_STOP_COMMAND       = 1ULL << 1;  // CPU stop/halt
inline constexpr uint64_t CPS_FIRMWARE_DOWNLOAD      = 1ULL << 2;  // Flashing firmware
inline constexpr uint64_t CPS_SAFETY_INTERLOCK_BYPASS= 1ULL << 3;  // SIS trip override
inline constexpr uint64_t CPS_TELEMETRY_SPOOF        = 1ULL << 4;  // PMU or sensor spoofing

inline constexpr uint64_t NET_REPLAY_ATTACK          = 1ULL << 10; // Sequence desynchronization
inline constexpr uint64_t NET_RECON_SWEEP            = 1ULL << 11; // Port or function enumeration
inline constexpr uint64_t NET_EXPLOIT_MALFORMED      = 1ULL << 12; // Length buffer mismatch

inline constexpr uint64_t IDENTITY_BRUTE_FORCE       = 1ULL << 20; // Repeated auth failures
inline constexpr uint64_t PRIVILEGE_ESCALATION       = 1ULL << 21; // Root/Admin credential swap
inline constexpr uint64_t ANOMALY_ZERO_DAY           = 1ULL << 30; // High residual AI deviation

} // namespace sentinel::sdk::tags