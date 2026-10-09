#include <sentinel/sdk/plugin.hpp>

using namespace sentinel::sdk;

static SentinelDissectorResult buggy_dissect(const SentinelRawPacket* /*raw_pkt*/) {
    // Deliberate Null Pointer Dereference
    volatile int* bad_ptr = reinterpret_cast<volatile int*>(0x0);
    *bad_ptr = 0xDEADBEEF; // Triggers instant SIGSEGV

    return VerdictBuilder::Pass();
}

static SentinelPluginDescriptor g_descriptor = {
    SENTINEL_SDK_MAGIC,
    SENTINEL_SDK_VERSION_MAJOR,
    SENTINEL_SDK_VERSION_MINOR,
    SENTINEL_TIER_NATIVE_CPP,
    "org.aryorithm.plugin.crash_test",
    "Deliberate Buggy Crasher",
    "1.0.0",
    "CRASH_TEST",
    0,
    0,
    nullptr,
    nullptr,
    buggy_dissect
};

SENTINEL_REGISTER_PLUGIN(g_descriptor)
