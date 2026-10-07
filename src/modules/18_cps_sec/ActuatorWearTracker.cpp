#include "ActuatorWearTracker.hpp"
#include <sstream>
#include <iomanip>

namespace sentinel::cps {

void ActuatorWearTracker::record_actuation(uint32_t register_address, 
                                          const std::string& plc_ip, 
                                          float commanded_value) {
    (void)commanded_value;
    std::lock_guard<std::mutex> lock(mutex_);

    auto now_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    auto& entry = actuators_[register_address];
    entry.register_address = register_address;
    entry.plc_ip = plc_ip;
    entry.total_actuations++;

    if (entry.last_actuated_ns > 0) {
        uint64_t delta_ns = now_ns - entry.last_actuated_ns;
        if (delta_ns > 0) {
            float instant_hz = 1'000'000'000.0f / static_cast<float>(delta_ns);
            // Exponential moving average for frequency
            entry.current_frequency_hz = (0.7f * entry.current_frequency_hz) + (0.3f * instant_hz);
        }
    }

    entry.last_actuated_ns = now_ns;
    entry.chatter_warning = (entry.current_frequency_hz > CHATTER_FREQUENCY_THRESHOLD_HZ);

    // Calculate fatigue score (e.g., rating based on 100,000 standard lifecycle operations)
    entry.mechanical_stress_score = std::min(1.0f, static_cast<float>(entry.total_actuations) / 100000.0f);
}

bool ActuatorWearTracker::get_actuator_metrics(uint32_t register_address, ActuatorMetrics& out_metrics) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = actuators_.find(register_address);
    if (it == actuators_.end()) return false;
    out_metrics = it->second;
    return true;
}

std::string ActuatorWearTracker::export_wear_telemetry_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream ss;
    ss << "[\n";

    size_t i = 0;
    for (const auto& [reg, m] : actuators_) {
        ss << "  {\n"
           << "    \"register_address\": " << m.register_address << ",\n"
           << "    \"plc_ip\": \"" << m.plc_ip << "\",\n"
           << "    \"total_actuations\": " << m.total_actuations << ",\n"
           << "    \"frequency_hz\": " << std::fixed << std::setprecision(2) << m.current_frequency_hz << ",\n"
           << "    \"chatter_warning\": " << (m.chatter_warning ? "true" : "false") << ",\n"
           << "    \"stress_fatigue_score\": " << std::fixed << std::setprecision(3) << m.mechanical_stress_score << "\n"
           << "  }" << (++i < actuators_.size() ? ",\n" : "\n");
    }

    ss << "]";
    return ss.str();
}

void ActuatorWearTracker::reset_wear_counter(uint32_t register_address) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = actuators_.find(register_address);
    if (it != actuators_.end()) {
        it->second.total_actuations = 0;
        it->second.mechanical_stress_score = 0.0f;
        it->second.chatter_warning = false;
    }
}

} // namespace sentinel::cps