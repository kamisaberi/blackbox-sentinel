#pragma once

#include "abi.hpp"
#include "packet_view.hpp"
#include "verdict.hpp"
#include "semantic_tags.hpp"
#include "host_api.h"

#define SENTINEL_PLUGIN_EXPORT extern "C" ARY_SDK_API

#define SENTINEL_REGISTER_PLUGIN(DescriptorSymbol)                     \
    SENTINEL_PLUGIN_EXPORT const SentinelPluginDescriptor*             \
    sentinel_plugin_get_descriptor(void) {                             \
        static_assert(                                                 \
            sizeof(DescriptorSymbol.magic) == sizeof(uint64_t),        \
            "Invalid Sentinel descriptor format"                       \
        );                                                             \
        return &(DescriptorSymbol);                                    \
    }