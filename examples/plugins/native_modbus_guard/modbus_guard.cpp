#include <sentinel/sdk/plugin.hpp>

using namespace sentinel::sdk;

static const SentinelHostInterface* g_host = nullptr;

static int modbus_guard_init(const SentinelHostInterface* host) {
    g_host = host;
    if (g_host && g_host->log_message) {
        g_host->log_message(SENTINEL_LOG_INFO, "ModbusGuard", "Initialized Modbus Guard Dissector");
    }
    return 0;
}

static void modbus_guard_shutdown(void) {
    if (g_host && g_host->log_message) {
        g_host->log_message(SENTINEL_LOG_INFO, "ModbusGuard", "Shut down Modbus Guard");
    }
}

static SentinelDissectorResult modbus_guard_dissect(const SentinelRawPacket* raw_pkt) {
    if (!raw_pkt || !raw_pkt->data || raw_pkt->length < 8) {
        return VerdictBuilder::Pass();
    }

    PacketView pkt(*raw_pkt);

    // Modbus TCP MBAP Header:
    // 0..1: Transaction ID
    // 2..3: Protocol ID (Must be 0x0000 for Modbus)
    // 4..5: Length (be16)
    // 6:    Unit ID
    // 7:    Function Code

    auto proto_id = pkt.read_be16(2);
    if (!proto_id.has_value() || proto_id.value() != 0x0000) {
        return VerdictBuilder::Pass(); // Not Modbus TCP
    }

    auto func_code = pkt.peek_u8(7);
    if (!func_code.has_value()) {
        return VerdictBuilder::Pass();
    }

    uint8_t fc = func_code.value();

    // Block Function Code 05 (Write Single Coil) and 15 (Write Multiple Coils)
    if (fc == 0x05 || fc == 0x0F) {
        if (g_host && g_host->emit_metric_counter) {
            g_host->emit_metric_counter("modbus.unauthorized_coil_write", 1);
        }

        return VerdictBuilder::Drop(1001, "UNAUTHORIZED_MODBUS_COIL_WRITE", 1.0f)
            .with_tag(tags::CPS_ACTUATOR_WRITE)
            .with_tag(tags::CPS_SAFETY_INTERLOCK_BYPASS)
            .build();
    }

    return VerdictBuilder::Pass();
}

static SentinelPluginDescriptor g_descriptor = {
    SENTINEL_SDK_MAGIC,
    SENTINEL_SDK_VERSION_MAJOR,
    SENTINEL_SDK_VERSION_MINOR,
    SENTINEL_TIER_NATIVE_CPP,
    "org.aryorithm.plugin.modbus_guard",
    "Modbus TCP Coil Guard",
    "1.0.0",
    "MODBUS_TCP",
    502,
    0,
    modbus_guard_init,
    modbus_guard_shutdown,
    modbus_guard_dissect
};

SENTINEL_REGISTER_PLUGIN(g_descriptor)