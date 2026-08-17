cmake_minimum_required(VERSION 3.20)
project(blackbox-sentinel VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optimization Flags
add_compile_options(-O3 -Wall -Wextra -pthread -march=native)

# Include Directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    /usr/local/include
)

# Find System & Shared Library Dependencies
find_package(Threads REQUIRED)
find_library(BLACKBOX_LIB blackbox REQUIRED PATHS /usr/local/lib /usr/lib)
find_library(XINFER_LIB xinfer REQUIRED PATHS /usr/local/lib /usr/lib)
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# Source Files
set(SENTINEL_SOURCES
    src/main.cpp
    src/api/auth_manager.cpp
    src/api/rest_controller.cpp
    src/hardware/hw_monitor.cpp
    src/hardware/tpm_license.cpp
    src/exporter/report_generator.cpp
)

# Build Commercial Appliance Executable
add_executable(sentinel ${SENTINEL_SOURCES})

# Link Libraries
target_link_libraries(sentinel PRIVATE
    ${BLACKBOX_LIB}
    ${XINFER_LIB}
    ${SQLITE3_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# RPATH so executable finds shared libraries in /usr/local/lib
set_target_properties(sentinel PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "/usr/local/lib"
)

install(TARGETS sentinel DESTINATION /usr/local/bin)