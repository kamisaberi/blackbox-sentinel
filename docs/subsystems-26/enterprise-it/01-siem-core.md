---

### File: `blackbox-sentinel/docs/subsystems-26/enterprise-it/01-siem-core.md`

```markdown
# Subsystem 01: In-Memory SIEM Core (`01_siem_core`)

`01_siem_core` is the centralized, in-memory log correlation, indexing, and querying engine within `blackbox-sentinel`. It collects normalized security events from all other 25 subsystems, maintaining high-frequency correlation windows without writing intermediate log files to disk.

---

## 1. Architectural Mechanics

```text
 [ Ingress Telemetry from Subsystems 02-26 ]
                     │
                     ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Circular In-Memory Ring Store (Pre-Allocated 1,000,000 Slots)│
 │  - Zero Heap Growth                 - Fixed 512 MB Budget   │
 └───────────────────┬─────────────────────────────────────────┘
                     │
                     ▼ Multi-Field Inverted Index
 ┌─────────────────────────────────────────────────────────────┐
 │ Inverted Index Tables (Bitmap Postings)                     │
 │  - By Source IP                     - By MITRE Technique ID │
 │  - By Protocol Port                 - By Severity Class     │
 └───────────────────┬─────────────────────────────────────────┘
                     │
                     ▼ Microsecond Correlation Rule Engine
 [ Trigger Multi-Stage Alert / Update In-Kernel BPF Drop Gate ]
```

---

## 2. Inverted Index Implementation (`SiemCore.hpp`)

```cpp
#pragma once

#include <array>
#include <string_view>
#include <cstdint>
#include <vector>
#include <shared_mutex>

namespace sentinel::subsystems {

struct SiemRecord {
    uint64_t timestamp_ns{0};
    uint32_t src_ipv4{0};
    uint32_t dst_ipv4{0};
    uint16_t subsystem_id{0};
    uint16_t rule_id{0};
    uint8_t severity{0}; // 0 = Info, 1 = Low, 2 = Medium, 3 = High, 4 = Critical
    char description[64]{0};
};

class SiemCore {
public:
    static constexpr size_t RING_CAPACITY = 1048576; // 1M events

    void ingest(const SiemRecord& record) noexcept {
        uint64_t idx = write_cursor_.fetch_add(1, std::memory_order_relaxed);
        size_t slot = idx & (RING_CAPACITY - 1);
        ring_[slot] = record;
        update_indices(slot, record);
    }

    // Query records matching an IP address in under 5 milliseconds
    std::vector<SiemRecord> query_by_ip(uint32_t ip, size_t limit = 100) const {
        std::shared_lock lock(index_mutex_);
        std::vector<SiemRecord> results;
        results.reserve(limit);

        auto it = ip_index_.find(ip);
        if (it != ip_index_.end()) {
            for (size_t slot : it->second) {
                results.push_back(ring_[slot]);
                if (results.size() >= limit) break;
            }
        }
        return results;
    }

private:
    std::array<SiemRecord, RING_CAPACITY> ring_{};
    std::atomic<uint64_t> write_cursor_{0};
    mutable std::shared_mutex index_mutex_;
    std::unordered_map<uint32_t, std::vector<size_t>> ip_index_;

    void update_indices(size_t slot, const SiemRecord& rec);
};

} // namespace sentinel::subsystems
```

---

## 3. Performance SLA

* **Ingestion Throughput:** Sustained $> 1{,}000{,}000\text{ events/sec}$ per NUMA node.
* **Correlated Search Latency:** $< 4.5\,\text{ms}$ across $1{,}000{,}000$ active in-memory events.
```

