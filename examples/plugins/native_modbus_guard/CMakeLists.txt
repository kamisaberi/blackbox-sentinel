cmake_minimum_required(VERSION 3.20)
project(sentinel_plugin_modbus_guard CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

# Find SDK headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_library(sentinel_plugin_modbus_guard SHARED
    modbus_guard.cpp
)

set_target_properties(sentinel_plugin_modbus_guard PROPERTIES
    PREFIX ""
    OUTPUT_NAME "sentinel_modbus_guard"
)