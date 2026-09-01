#pragma once

#include <blackbox/event.hpp>
#include <string>

namespace sentinel::plugin {

enum class SentinelPluginType {
    ProtocolInspector, // SCADA Modbus, DNP3, Profinet, MAVLink
    DeceptionTrap,     // Honeypot decoy ports, fake portals
    Forensics,         // PCAP Evidence Carver, Memory Dumper
    SOCBridge,         // Splunk/QRadar CEF forwarders, Firewall sync
    PhysicalSecurity   // Camera tamper checker, GPIO sirens
};

class ISentinelPlugin {
public:
    virtual ~ISentinelPlugin() = default;

    virtual const char* get_name() const = 0;
    virtual const char* get_version() const = 0;
    virtual SentinelPluginType get_type() const = 0;

    virtual bool initialize(const std::string& config_json) = 0;
    virtual void process_event(blackbox::SecurityEvent& event) = 0;
    virtual void shutdown() = 0;
};

// C-linkage symbols for Linux dlopen() / dlsym() loading
typedef ISentinelPlugin* (*CreateSentinelPluginFunc)();
typedef void (*DestroySentinelPluginFunc)(ISentinelPlugin*);

} // namespace sentinel::plugin