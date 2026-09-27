#pragma once
#include <string>
#include <array>
#include <sstream>
#include <iomanip>

namespace sentinel::xai {

struct FeatureSemantic {
    const char* name;
    const char* physical_unit;
    float baseline_mean;
    float baseline_std;
    const char* audit_summary;
};

// Zero-allocation static semantic dictionary mapping 32 NetFlow/CPS dimensions
inline constexpr std::array<FeatureSemantic, 32> SEMANTIC_DICTIONARY = {{
    {"Flow_Duration_us", "us", 12450.0f, 3200.0f, "Session duration significantly breached nominal bounds"},
    {"Total_Fwd_Packets", "pkts", 8.4f, 2.1f, "Abnormal packet burst volume in forward direction"},
    {"Total_Bwd_Packets", "pkts", 7.2f, 1.9f, "Abnormal backward response packet count"},
    {"Total_Fwd_Bytes", "bytes", 1024.0f, 256.0f, "Excessive payload byte volume transferred"},
    {"Forward_Packet_Rate", "Hz", 18.4f, 4.2f, "High-velocity command injection rate exceeded threshold by >10x"},
    {"Backward_Packet_Rate", "Hz", 15.2f, 3.8f, "Anomalous automated server response velocity"},
    {"Flow_Bytes_Per_Sec", "B/s", 4200.0f, 850.0f, "Line throughput velocity exceeded safety baseline"},
    {"TCP_SYN_Flag_Ratio", "%", 1.2f, 0.4f, "Stealth half-open TCP port reconnaissance detected"},
    {"TCP_RST_Flag_Ratio", "%", 0.5f, 0.2f, "Abnormal connection teardown frequency indicating port probing"},
    {"TCP_PSH_Flag_Ratio", "%", 12.0f, 3.0f, "High-urgency data push flags indicating automated scripting"},
    {"TCP_ACK_Flag_Ratio", "%", 85.0f, 5.0f, "TCP handshake sequence deviation"},
    {"Avg_Packet_Size", "bytes", 240.0f, 45.0f, "Non-standard frame length violating protocol MTU expectation"},
    {"SCADA_Function_Code", "enum", 3.0f, 0.0f, "Unauthorized function code attempting physical actuator write"},
    {"SCADA_Sub_Function", "enum", 0.0f, 0.0f, "Restricted protocol sub-function invocation"},
    {"SCADA_Unit_Identifier", "id", 1.0f, 0.0f, "Target unit corresponds to isolated physical safety sub-loop"},
    {"SCADA_Register_Address", "addr", 50.0f, 20.0f, "Targeted register belongs to restricted physical actuation zone"},
    {"SCADA_Register_Count", "count", 4.0f, 1.0f, "Mass register read/write sweep attempting memory dump"},
    {"SCADA_Exception_Code", "code", 0.0f, 0.0f, "Protocol slave emitted critical constraint violation exception"},
    {"Payload_Shannon_Entropy", "bits", 3.84f, 0.42f, "High-entropy payload (>7.5) indicating encrypted C2 or ransomware"},
    {"Payload_Byte_Variance", "var", 45.2f, 8.1f, "Anomalous payload randomness distribution"},
    {"Header_Length_Ratio", "%", 14.5f, 2.0f, "Anomalous header encapsulation length"},
    {"TCP_Window_Zero_Count", "count", 0.0f, 0.0f, "TCP zero-window exhaustion attempt starving PLC buffer"},
    {"Initial_Window_Bytes", "bytes", 65535.0f, 0.0f, "Non-standard TCP stack fingerprint indicating automated scanner"},
    {"Active_Mean_Duration", "ms", 120.0f, 25.0f, "Continuous high-duty actuation flow session"},
    {"Idle_Mean_Duration", "ms", 850.0f, 120.0f, "Absence of required periodic keep-alive telemetry"},
    {"Inter_Arrival_Jitter", "ms", 45.2f, 12.1f, "Extremely low jitter (<0.1ms) proving automated non-human timing"},
    {"Fwd_Segment_Size_Avg", "bytes", 128.0f, 24.0f, "Fragmented payload structure attempting IDS evasion"},
    {"Bwd_Segment_Size_Avg", "bytes", 128.0f, 24.0f, "Anomalous response packet chunking"},
    {"TLS_JA4_Hash_Variance", "hash", 0.0f, 0.0f, "Unapproved or blacklisted TLS client cipher suite"},
    {"DNS_Query_Entropy", "bits", 2.1f, 0.3f, "High-entropy domain name indicating DGA C2 algorithm"},
    {"ICMP_Payload_Size", "bytes", 32.0f, 0.0f, "Abnormal ICMP echo payload indicating covert tunnel exfiltration"},
    {"Protocol_Anomaly_Index", "score", 0.05f, 0.02f, "Composite physical state constraint violation score"}
}};

} // namespace sentinel::xai