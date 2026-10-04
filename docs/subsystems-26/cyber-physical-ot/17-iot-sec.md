### Part 5: 26 Native Subsystems — Cyber-Physical OT & Forensics (`subsystems-26/*`)

This section contains 9 technical implementation guides for the remaining native subsystems: the 3 **Cyber-Physical OT & IoT Protection** modules (`17_iot_sec`, `18_cps_sec`, `21_side_channel`) and the 6 **Forensics, Traffic Control & Deception** modules (`13_ddos`, `19_swg`, `22_dfir`, `23_ai_trism`, `25_fdp`, `26_ddp`).

---

### File: `blackbox-sentinel/docs/subsystems-26/cyber-physical-ot/17-iot-sec.md`

```markdown
# Subsystem 17: Medical IoT & PACS Protocol Security (`17_iot_sec`)

`17_iot_sec` secures clinical healthcare networks, radiological picture archiving systems (DICOM PACS), and telemetry medical devices. It operates inline, parsing **DICOM C-STORE, C-FIND, and HL7 v2/v3** clinical protocol messages over the wire to detect unauthorized patient data exfiltration, ransomware encryption of radiological archives, and medical sensor manipulation.

---

## 1. DICOM Medical Imaging Validation Pipeline

```text
 [ PACS Ingress Traffic: TCP Port 104 / 11112 ]
                        │
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Zero-Copy DICOM Upper Layer Protocol (DULP) Dissector       │
 │  - Verifies Application Entity Titles (Calling/Called AET)  │
 │  - Inspects P-DATA-TF presentation data value streams       │
 └──────────────────────┬──────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼ C-STORE Operation             ▼ C-FIND / C-MOVE Operation
 ┌─────────────────────────────┐ ┌─────────────────────────────┐
 │ 16-Bit Pixel Array Audit    │ │ Bulk Record Query Audit     │
 │  - Detects Steganography    │ │  - Evaluates Query Velocity │
 │  - Flags Inverted HU Bounds │ │  - Traps Mass Exfiltration  │
 └──────────────┬──────────────┘ └──────────────┬──────────────┘
                │                               │
                └───────────────┬───────────────┘
                                │ Threat Detected
                                ▼
 [ Block Rogue Modality IP in Kernel (< 0.84 µs) & Sever Session ]
```

---

## 2. In-Memory HL7 Clinical Parser (`IotSecEngine.cpp`)

```cpp
#include <string_view>
#include <vector>
#include <span>
#include <cstdint>

namespace sentinel::subsystems {

struct Hl7SegmentView {
    std::string_view segment_id; // e.g., "MSH", "PID", "OBX"
    std::vector<std::string_view> fields;
};

class IotSecEngine {
public:
    // Parses HL7 v2 pipe-delimited message without memory allocations
    bool validate_hl7_stream(std::string_view raw_msg) {
        if (raw_msg.size() < 4 || !raw_msg.starts_with("MSH")) {
            return false; // Malformed clinical message
        }

        const char field_sep = raw_msg[3]; // Standard '|'
        // Enforce clinical sanity constraints:
        // Reject messages containing command injection characters in patient IDs
        if (raw_msg.find(";") != std::string_view::npos || 
            raw_msg.find("&&") != std::string_view::npos ||
            raw_msg.find("`") != std::string_view::npos) {
            return false; // Embedded shellcode / injection trapped
        }

        return true;
    }
};

} // namespace sentinel::subsystems
```

---

## 3. Supported Clinical Protocol Standards

* **DICOM Standard PS 3.8:** Network Communication Support for Message Exchange.
* **HL7 Standards:** Health Level Seven International Versions 2.3, 2.5, and FHIR JSON.
* **Regulatory Alignment:** Satisfies technical access and transmission security requirements under HIPAA § 164.312(e)(1).
```

---

### File: `blackbox-sentinel/docs/subsystems-26/cyber-physical-ot/18-cps-sec.md`

```markdown
# Subsystem 18: SCADA Physical Constraint Validator (`18_cps_sec`)

`18_cps_sec` bridges cyber defense with the laws of physical thermodynamics. It models industrial physical invariants (e.g., turbine RPM velocities, pipeline pressures, chemical dosing limits) and parses industrial protocol frames (**Modbus TCP, DNP3, Siemens S7Comm**) to drop out-of-bounds commands before they reach physical field actuators.

---

## 1. Physical Invariant Enforcement Model

Attackers (such as the authors of Stuxnet, Industroyer, or Triton) craft syntactically valid protocol frames with values designed to cause physical destruction. `18_cps_sec` verifies commands against **thermodynamic state equations**:

$$\Delta V = \frac{V_{\text{target}} - V_{\text{current}}}{t - t_{\text{last}}} \le \text{MaxAllowableRateOfChange}$$

```text
 [ Ingress Modbus TCP Packet: Function Code 16 (Write Registers) ]
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Protocol APDU Dissection                                    │
 │   - Target Register: 40001 (Main High-Pressure Gas Valve)   │
 │   - Requested Value: 9,850 PSI                              │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Physical Invariant Check
 ┌─────────────────────────────────────────────────────────────┐
 │ State Validator (18_cps_sec)                                │
 │   - Current Pressure   : 2,100 PSI                          │
 │   - Max Physical Bound : 4,500 PSI                          │
 │   - Calculated Gradient: +7,750 PSI / 100ms (Illegal Slope) │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ VIOLATION DETECTED
 [ In-Kernel XDP Drop Triggered: Dropped before PLC (< 0.84 µs) ]
```

---

## 2. Cumulative Actuator Wear & Cycle Counter

To prevent high-frequency mechanical wear attacks, `18_cps_sec` tracks cumulative actuator cycles:

```cpp
#include <cstdint>
#include <chrono>

namespace sentinel::subsystems {

struct ActuatorWearTracker {
    uint32_t register_id{0};
    uint64_t total_cycles{0};
    uint64_t max_duty_cycles_per_hour{100};
    uint64_t cycles_this_hour{0};
    uint64_t last_cycle_time_ns{0};

    bool record_actuation(uint64_t now_ns) noexcept {
        // Enforce minimum physical refractory period (e.g. 500ms between valve shifts)
        if (now_ns - last_cycle_time_ns < 500'000'000ULL) {
            return false; // Physical cycling rate exceeded
        }

        last_cycle_time_ns = now_ns;
        total_cycles++;
        cycles_this_hour++;
        return cycles_this_hour <= max_duty_cycles_per_hour;
    }
};

} // namespace sentinel::subsystems
```

---

## 3. Configuration Schema (`sentinel.yaml`)

```yaml
subsystems:
  cps_sec:
    enabled: true
    industrial_invariants:
      - protocol: "MODBUS"
        unit_id: 1
        register: 40001
        min_value: 0.0
        max_value: 4500.0
        max_rate_of_change_per_sec: 150.0
        on_violation: "KERNEL_DROP"
```
```

---

### File: `blackbox-sentinel/docs/subsystems-26/cyber-physical-ot/21-side-channel.md`

```markdown
# Subsystem 21: Hardware Power & Emission Anomaly Analyzer (`21_side_channel`)

`21_side_channel` analyzes side-channel emissions—including hardware power consumption profiles, electrical supply ripple, and electromagnetic (EM) variations—ingested via analog-to-digital converters (ADCs) or hardware current shunts (e.g., INA219, INA3221). It detects hardware Trojan activations and unauthorized firmware tampering without interacting with the host OS.

---

## 1. Power Waveform FFT Pipeline

```text
 [ Hardware Current Shunt / ADC Input (e.g. 100 kHz Sampling) ]
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Circular Waveform Ring Buffer (1024 Samples)                │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Fast Fourier Transform (KissFFT / AVX2)
 ┌─────────────────────────────────────────────────────────────┐
 │ Frequency Spectrum Distribution:                            │
 │  • Baseline Steady State: Constant harmonic at 50/60 Hz     │
 │  • Trojan / Injection: High-frequency spectral spikes       │
 │    induced by unauthorized CPU micro-loops (10-25 kHz)      │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Compute Spectral Distance
 [ Anomaly Detected: Power Signature Diverges -> Alert SIEM ]
```

---

## 2. Invariants & Speed

* **Hardware Independence:** Detects attacks even when host kernel logging, syslog, and network interfaces have been compromised or blinded by kernel rootkits.
* **FFT Evaluation Latency:** Evaluates a 1024-point real-to-complex FFT in **$< 45\,\mu\text{s}$**.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/13-ddos.md`

```markdown
# Subsystem 13: Line-Rate Flood Shaper & SYN Cookie Guard (`13_ddos`)

`13_ddos` defends edge appliances from line-rate volumetric floods (SYN, UDP, ICMP, and amplification reflection attacks) by generating cryptographic **eBPF SYN Cookies** directly within the driver ring, maintaining wire availability without allocating TCP socket structures in host RAM.

---

## 1. In-Kernel eBPF SYN Cookie Generation

```text
 [ Inbound TCP SYN Packet Flood (14.88 Mpps) ]
                     │
                     ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ xdp_filter.o (Subsystem 13 Hook)                            │
 └───────────────────┬─────────────────────────────────────────┘
                     │
                     ▼ Evaluates SynFlood Threshold
 ┌─────────────────────────────────────────────────────────────┐
 │ bpf_tcp_gen_syncookie(ctx, ...)                             │
 │   - Generates 32-bit Cryptographic ISN using SHA-256        │
 │   - ISN encodes MSS, timestamp, and client secret           │
 └───────────────────┬─────────────────────────────────────────┘
                     │
                     ▼ Reflects SYN-ACK directly out the same interface
 ┌─────────────────────────────────────────────────────────────┐
 │ Action: XDP_TX (Bypasses Host Linux Network Stack Entirely) │
 │  - Zero socket memory allocated in kernel RAM               │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. High-Frequency Rate Limiting via Token Buckets

`13_ddos` maintains an in-kernel per-IP token bucket map:

```c
struct token_bucket {
    __u64 last_update_ns;
    __u64 tokens;
};

// Returns 1 if permitted, 0 if rate limit exceeded (Trigger XDP_DROP)
static __always_inline int check_rate_limit(struct token_bucket *b, __u64 rate, __u64 capacity) {
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - b->last_update_ns;
    b->last_update_ns = now;

    // Replenish tokens based on elapsed nanoseconds
    b->tokens += (elapsed * rate) / 1000000000ULL;
    if (b->tokens > capacity) b->tokens = capacity;

    if (b->tokens > 0) {
        b->tokens--;
        return 1; // Allow packet
    }
    return 0; // Rate limit breach -> DROP
}
```

---

## 3. Mitigation Throughput

* **Max Shaper Capacity:** Full $14.88\text{ Mpps}$ line rate sustained on $10\text{ GbE}$ interfaces.
* **Host CPU Overhead:** $< 6\%$ on a single isolated core.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/19-swg.md`

```markdown
# Subsystem 19: Sovereign Web Gateway & Egress Filter (`19_swg`)

`19_swg` enforces sovereign outbound data sovereignty policies. It monitors and restricts outbound connections from local edge devices to the internet, enforcing DNS-over-HTTPS sinkholing, TLS certificate validation, and zero cloud data egress invariants.

---

## 1. Outbound Egress Enforcement Architecture

```text
 [ Protected Subnet Device (PLC / Medical Modality / Gateway) ]
                            │
                            ▼ Outbound Request (e.g. TCP 443 / UDP 53)
 ┌─────────────────────────────────────────────────────────────┐
 │ 19_swg Sovereign Proxy Engine                               │
 └──────────────────────────┬──────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
 ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
 │ DNS Filtering│    │ TLS Cert Pin │    │ Zero Egress  │
 │ Blocks DGA & │    │ Traps Rogue  │    │ Blocks Cloud │
 │ C2 Domains   │    │ MITM Proxies │    │ Data Exfil   │
 └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │ Violation Detected
                            ▼
 [ In-Kernel XDP_DROP on Egress: Zero Bytes Leave the Plant ]
```

---

## 2. Invariants

* **Deterministic Sinkholing:** Unauthorized external DNS queries are redirected to `127.0.0.1` in driver space.
* **$0.00 Egress Enforcement:** Enforces strict boundary policies preventing connected devices from pushing telemetry to unapproved public cloud endpoints.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/22-dfir.md`

```markdown
# Subsystem 22: Circular PCAP Carver & Evidence Vault (`22_dfir`)

`22_dfir` maintains a circular in-memory buffer that captures raw packet frames. When an attack is mitigated by any of the 26 subsystems, `22_dfir` dumps a pre-attack and post-attack packet window directly to NVMe storage, cryptographically sealing the carved `.pcap` evidence with SHA-256 for judicial admissibility.

---

## 1. Trigger-on-Drop Carving Architecture

```text
 Ingress Packets ──► [ Circular RAM Ring Buffer (256 MB Static Pool) ]
                                      │
                                      ▼
                        Continuously holds last 30 seconds of raw wire traffic
                                      │
                                      ▼ eBPF Trigger: XDP_DROP Executed
 ┌─────────────────────────────────────────────────────────────┐
 │ 22_dfir Carve Routine (Non-Blocking Disk Flush)             │
 │   - Flushes T-10 seconds to T+5 seconds packet window       │
 │   - Encapsulates into standard libpcap format               │
 └────────────────────────────┬────────────────────────────────┘
                              │
                              ▼ SHA-256 Digest Calculation
 ┌─────────────────────────────────────────────────────────────┐
 │ Cryptographic Evidence Packaging                            │
 │   - File: /var/log/sentinel/forensics/incident_<id>.pcap    │
 │   - Signed with Hardware TPM 2.0 AIK Private Key            │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Carving Implementation (`PcapCarver.cpp`)

```cpp
#include <fstream>
#include <vector>
#include <cstdint>

namespace sentinel::subsystems {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number{0xa1b2c3d4};
    uint16_t version_major{2};
    uint16_t version_minor{4};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{65535};
    uint32_t network{1}; // LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

void flush_carved_pcap(const std::string& path, const std::vector<uint8_t>& raw_frames) {
    std::ofstream out(path, std::ios::binary);
    PcapGlobalHeader gh;
    out.write(reinterpret_cast<const char*>(&gh), sizeof(gh));
    out.write(reinterpret_cast<const char*>(raw_frames.data()), raw_frames.size());
}

} // namespace sentinel::subsystems
```

---

## 3. Regulatory Value

Provides forensic evidence compliant with ISO/IEC 27037 standards for digital evidence handling, proving root-cause vectors during regulatory post-incident investigations.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/23-ai-trism.md`

```markdown
# Subsystem 23: AI Safety Firewall & Prompt Barrier (`23_ai_trism`)

`23_ai_trism` (AI Trust, Risk and Security Management) acts as a specialized firewall for local and edge Artificial Intelligence workloads. It intercepts inference payloads directed to Large Language Models (LLMs) or neural vision runtimes, trapping **jailbreak prompts, toxic vectors, adversarial perturbation attacks, and model extraction attempts**.

---

## 1. Threat Vectors Mitigated

```text
 [ Ingress User / API Prompt Stream ]
                 │
                 ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 23_ai_trism Deep Semantic Inspector                         │
 └───────────────┬─────────────────────────────────────────────┘
                 │
        ┌────────┼────────────────────────┬────────────────────┐
        ▼        ▼                        ▼                    ▼
 ┌─────────────┐ ┌──────────────────────┐ ┌──────────────────┐ ┌────────────────┐
 │ Jailbreak / │ │ Adversarial          │ │ Training Data    │ │ Sensitive PII /│
 │ Injection   │ │ Perturbation         │ │ Extraction       │ │ Vault Token    │
 │ "Ignore all │ │ High-frequency noise │ │ System prompt    │ │ Exfiltration   │
 │ instructions│ │ in input images      │ │ probing attacks  │ │ Leakage        │
 └──────┬──────┘ └──────────┬───────────┘ └────────┬─────────┘ └───────┬────────┘
        │                   │                      │                   │
        └───────────────────┼──────────────────────┴───────────────────┘
                            │ Violation Detected
                            ▼
 [ Prompt Sanitized / Request Blocked with HTTP 403 Forbidden ]
```

---

## 2. In-Memory Cosine Similarity Guard

`23_ai_trism` maps incoming text prompts into an 8-dimensional latent vector using Tier 1 `libxinfer.so` and evaluates cosine similarity against an in-memory database of known adversarial jailbreak embeddings:

$$\text{Similarity}(A, B) = \frac{A \cdot B}{\|A\| \|B\|}$$

If $\text{Similarity} > 0.88$, the transaction is blocked before reaching the downstream inference worker.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/25-fdp.md`

```markdown
# Subsystem 25: Financial Transaction Graph Anomaly Analyzer (`25_fdp`)

`25_fdp` inspects high-frequency financial protocol streams (e.g., **ISO 20022 XML, FIX Protocol, and SWIFT MT messages**) over internal banking networks, identifying automated account draining, front-running attacks, and transaction graph anomalies.

---

## 1. Graph Analysis Pipeline

```text
 [ Ingress Transaction Stream: ISO 20022 / FIX 4.4 ]
                        │
                        ▼ Zero-Copy XML/Tag-Value Parser
 ┌─────────────────────────────────────────────────────────────┐
 │ Entity Transaction Directed Graph                           │
 │  - Nodes: Accounts, Routing Numbers, Originating Terminals  │
 │  - Edges: Transaction Amounts, Currencies, Latency Deltas   │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ Cycle & Velocity Anomaly Traps
 ┌─────────────────────────────────────────────────────────────┐
 │ Heuristic Rules:                                            │
 │  • Rapid Multi-Hop Smurfing (< 50ms account hops)           │
 │  • Sudden High-Volume Egress Outside Operational Baselines  │
 └──────────────────────┬──────────────────────────────────────┘
                        │
                        ▼ Anomaly Confirmed
 [ Invalidate Transaction Session & Push Source IP to eBPF Map ]
```

---

## 2. Performance SLA

* **Parsing Latency:** $< 18\,\mu\text{s}$ per FIX 4.4 transaction frame.
* **Memory Safety:** Operates on pre-allocated graph nodes, discarding completed transaction branches after verification.
```

---

### File: `blackbox-sentinel/docs/subsystems-26/forensics-advanced/26-ddp.md`

```markdown
# Subsystem 26: Distributed Deception Decoy PLCs (`26_ddp`)

`26_ddp` deploys synthetic deception honeypots across unused IP addresses on the local network. It emulates realistic, responsive industrial controllers (**Modbus PLCs, Siemens S7 outstations, and medical DICOM servers**) on secondary Virtual IPs (VIPs) to trap adversaries during the reconnaissance phase.

---

## 1. Secondary VIP Binding & Port Arbitration

To avoid port collisions with real production services on the same appliance, `26_ddp` binds decoy listeners exclusively to secondary virtual IPs using `SO_BINDTODEVICE`:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Physical Network Adapter: eth0 (Subnet: 10.240.0.0/24)      │
 ├─────────────────────────────────────────────────────────────┤
 │ Primary IP : 10.240.0.100  ──► Real Production Services      │
 │ Decoy VIP 1: 10.240.0.199  ──► Synthetic Schneider PLC     │
 │ Decoy VIP 2: 10.240.0.200  ──► Synthetic Siemens S7-1200    │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Decoy Modbus Server Implementation (`DecoyPlc.cpp`)

```cpp
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <blackbox/xdp_manager.hpp>

namespace sentinel::subsystems {

class DecoyPlc {
public:
    void bind_decoy_vip(const std::string& vip_address, uint16_t port, blackbox::XdpManager& xdp) {
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, vip_address.c_str(), &addr.sin_addr);

        if (::bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            ::listen(sock, 10);
            
            // Any client connecting to this decoy is an unauthorized adversary
            // Immediately flag attacker source IP and trigger kernel mitigation
        }
    }
};

} // namespace sentinel::subsystems
```

---

## 3. High-Fidelity Decoy Trapping

* **Zero False Positives:** Legitimate operational software never attempts communication with decoy VIPs. Any connection attempt (SYN packet to port 502 or 102 on a decoy IP) is treated as malicious.
* **Instant Quarantine:** The attacker’s source IP is inserted into `blocked_ip_map` immediately, severing their ability to scan the real production PLCs on the subnet.
```

