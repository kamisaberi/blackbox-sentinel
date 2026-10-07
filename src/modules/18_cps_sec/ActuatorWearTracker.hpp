#pragma once
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <chrono>

namespace sentinel::cps {

struct ActuatorMetrics {
    uint32_t register_address;
    std::string plc_ip;
    uint64_t total_actuations{0};
    uint64_t last_actuated_ns{0};
    float current_frequency_hz{0.0f};
    bool chatter_warning{false};
    float mechanical_stress_score{0.0f}; // 0.0 to 1.0 (Wear fatigue)
};

class ActuatorWearTracker {
public:
    static ActuatorWearTracker& instance() {
        static ActuatorWearTracker inst;
        return inst;
    }

    // Records a physical write / toggle event on a coil or holding register
    void record_actuation(uint32_t register_address, 
                          const std::string& plc_ip, 
                          float commanded_value);

    // Queries metrics for a specific register
    bool get_actuator_metrics(uint32_t register_address, ActuatorMetrics& out_metrics) const;

    // Serializes long-term actuator fatigue and wear data to JSON for cloud telemetry
    std::string export_wear_telemetry_json() const;

    // Resets counters (e.g., after physical maintenance of the valve/relay)
    void reset_wear_counter(uint32_t register_address);

private:
    ActuatorWearTracker() = default;

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, ActuatorMetrics> actuators_;
    const float CHATTER_FREQUENCY_THRESHOLD_HZ{35.0f}; // >35 Hz triggers mechanical chatter alarm
};

} // namespace sentinel::cps