# Memory Safety Invariants & Zero Heap Fragmentation

Edge security appliances deployed in mission-critical environments must run continuously for months or years without degradation. Traditional C/C++ daemons often succumb to heap fragmentation, memory leaks, and unbounded virtual memory expansion over time.

`blackbox-sentinel` enforces strict **memory safety invariants** across all 26 subsystems.

---

## 1. Zero Dynamic Allocation on the Fast Path

During steady-state packet evaluation, no subsystem is permitted to invoke `malloc()`, `calloc()`, `new`, or standard dynamic resizing operations (e.g., `std::vector::push_back` beyond capacity):

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Appliance Initialization Phase:                             │
 │  - Pre-allocates all 26 subsystem state matrices            │
 │  - Pins memory pools via mlock()                            │
 │  - Reserves ring buffer slots and scratchpads               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ TRANSITION TO ACTIVE STEADY-STATE
 ┌─────────────────────────────────────────────────────────────┐
 │ Operational Packet Mitigation Phase:                        │
 │  - Zero heap allocations                                    │
 │  - Fixed-size circular slot reuse                           │
 │  - RAII-scoped stack variables only                         │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Fixed-Capacity State Matrices

Subsystems that track state over time (such as User and Entity Behavior Analytics, `02_ueba`, and Network Detection, `03_ndr`) maintain fixed-capacity circular maps:

```cpp
#include <array>
#include <atomic>
#include <cstdint>

namespace sentinel {

template <typename Key, typename Value, size_t Capacity>
class FixedStateMatrix {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");

public:
    Value* acquire_or_evict(const Key& key) noexcept {
        size_t bucket = hash(key) & (Capacity - 1);
        // Eviction policy operates within statically pre-allocated memory
        entries_[bucket].key = key;
        entries_[bucket].last_seen = get_timestamp();
        return &entries_[bucket].value;
    }

private:
    struct Entry {
        Key key{};
        Value value{};
        uint64_t last_seen{0};
    };

    std::array<Entry, Capacity> entries_{};
};

} // namespace sentinel
```

---

## 3. Resident Set Size (RSS) Bounding

* **Maximum Permitted RAM Footprint:** Configured strictly via `/etc/sentinel/sentinel.yaml` (default: $2.0\text{ GB}$).
* **Memory Pool Overcommit Prevention:** If an unexpected traffic surge occurs, excess telemetry events trigger **Tail Drop** inside the SPMC ring buffer rather than dynamic memory expansion, preventing host kernel Out-of-Memory (OOM) panic events.

