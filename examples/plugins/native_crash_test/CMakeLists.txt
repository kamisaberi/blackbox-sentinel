cmake_minimum_required(VERSION 3.20)
project(sentinel_plugin_crash_test CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../include)
add_library(sentinel_crash_test SHARED crash_plugin.cpp)
set_target_properties(sentinel_crash_test PROPERTIES PREFIX "" OUTPUT_NAME "sentinel_crash_test")
