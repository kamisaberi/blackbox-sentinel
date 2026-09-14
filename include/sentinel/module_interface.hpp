#pragma once

#include <blackbox/event.hpp>
#include <string>

namespace sentinel {

enum class ModuleID {
    SIEM_CORE = 1,     // [01] SIEM Core Log Correlation & Time-Series
    UEBA = 2,          // [02] User & Entity Behavior Analytics
    NDR = 3,           // [03] Network Detection & Response / ETA
    IDS_IPS = 4,       // [04] Inline Intrusion Detection & Prevention
    WAF = 5,           // [05] Web Application & API Protection
    EDR = 6,           // [06] Endpoint Detection & Response
    EPP_NGAV = 7,      // [07] Next-Gen Antivirus & File Entropy
    NAC = 8,           // [08] Network Access Control & Device Profiling
    CWPP = 9,          // [09] Container eBPF Syscall Guard
    BAD = 10,          // [10] Bot & Automated Abuse Defense
    RASP = 11,         // [11] Runtime Application Self-Protection
    ITDR = 12,         // [12] Identity Threat Detection & Response
    DDOS = 13,         // [13] Hardware Line-Rate DDoS Mitigation
    ATO = 14,          // [14] Account Takeover Defense
    NGFW = 15,         // [15] Next-Generation Firewall & Deep Packet Inspection
    CDR = 16,          // [16] Content Disarm & Reconstruction
    IOT_SEC = 17,      // [17] IoT & Medical Device (IoMT) Defense
    CPS_SEC = 18,      // [18] Cyber-Physical & SCADA OT Defense
    SWG = 19,          // [19] Secure Web Gateway
    FSE = 20,          // [20] Firmware Security Evaluation
    SIDE_CHANNEL = 21, // [21] Hardware Side-Channel Defense
    DFIR = 22,         // [22] Digital Forensics & Incident Response
    AI_TRISM = 23,     // [23] AI Trust, Risk & LLM Prompt Firewall
    ZTNA = 24,         // [24] Zero Trust Network Access
    FDP = 25,          // [25] Fraud Detection & Prevention
    DDP = 26           // [26] Distributed Deception Honeypots
};

inline std::string module_id_to_string(ModuleID id) {
    switch (id) {
        case ModuleID::SIEM_CORE:     return "01_siem_core";
        case ModuleID::UEBA:          return "02_ueba";
        case ModuleID::NDR:           return "03_ndr";
        case ModuleID::IDS_IPS:       return "04_ids_ips";
        case ModuleID::WAF:           return "05_waf";
        case ModuleID::EDR:           return "06_edr";
        case ModuleID::EPP_NGAV:      return "07_epp_ngav";
        case ModuleID::NAC:           return "08_nac";
        case ModuleID::CWPP:          return "09_cwpp";
        case ModuleID::BAD:           return "10_bad";
        case ModuleID::RASP:          return "11_rasp";
        case ModuleID::ITDR:          return "12_itdr";
        case ModuleID::DDOS:          return "13_ddos";
        case ModuleID::ATO:           return "14_ato";
        case ModuleID::NGFW:          return "15_ngfw";
        case ModuleID::CDR:           return "16_cdr";
        case ModuleID::IOT_SEC:       return "17_iot_sec";
        case ModuleID::CPS_SEC:       return "18_cps_sec";
        case ModuleID::SWG:           return "19_swg";
        case ModuleID::FSE:           return "20_fse";
        case ModuleID::SIDE_CHANNEL:  return "21_side_channel";
        case ModuleID::DFIR:          return "22_dfir";
        case ModuleID::AI_TRISM:      return "23_ai_trism";
        case ModuleID::ZTNA:          return "24_ztna";
        case ModuleID::FDP:           return "25_fdp";
        case ModuleID::DDP:           return "26_ddp";
        default:                      return "unknown_module";
    }
}

class ISentinelModule {
public:
    virtual ~ISentinelModule() = default;

    virtual ModuleID get_id() const = 0;
    virtual const char* get_name() const = 0;

    // Lifecycle Management
    virtual bool initialize(const std::string& config_json) = 0;
    virtual bool start() = 0;
    virtual void stop() = 0;

    // Asynchronous Event Processing: Invoked via EventBus
    virtual void on_security_event(blackbox::SecurityEvent& event) = 0;

    // Health Diagnostic Check
    virtual bool is_healthy() const = 0;
};

} // namespace sentinel