cmake_minimum_required(VERSION 3.20)
project(blackbox-sentinel VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optimization Flags
add_compile_options(-O3 -Wall -Wextra -pthread -march=native)


# RPATH Settings so binaries find libblackbox.so and libxinfer.so at runtime
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "/usr/local/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)


# Include Directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    /usr/local/include
)




# Find System & Shared Library Dependencies
find_package(Threads REQUIRED)
find_library(BLACKBOX_LIB blackbox REQUIRED PATHS /usr/local/lib /usr/lib)
find_library(XINFER_LIB xinfer REQUIRED PATHS /usr/local/lib /usr/lib)
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(BPF_LIB bpf REQUIRED)
find_library(ELF_LIB elf REQUIRED)


# Create Imported CMake Target Alias for blackbox::blackbox
if(NOT TARGET blackbox::blackbox)
    add_library(blackbox::blackbox SHARED IMPORTED)
    set_target_properties(blackbox::blackbox PROPERTIES
        IMPORTED_LOCATION "${BLACKBOX_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
    )
endif()

# Source Files
set(SENTINEL_SOURCES
    src/main.cpp
    src/plugin_manager.cpp       # <--- ADDED PLUGIN MANAGER
    src/api/auth_manager.cpp
    src/api/rest_controller.cpp
    src/api/ws_streamer.cpp
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
    ${CMAKE_DL_LIBS}               # <--- LINKED DYNAMIC LOADING (-ldl)
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# RPATH so executable finds shared libraries in /usr/local/lib
set_target_properties(sentinel PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "/usr/local/lib"
)

# Helper macro for Commercial Plugins
macro(add_sentinel_plugin PLUGIN_TARGET SOURCE_FILE)
    add_library(${PLUGIN_TARGET} SHARED ${SOURCE_FILE})
    target_link_libraries(${PLUGIN_TARGET} PRIVATE blackbox::blackbox)
endmacro()


# ----------------------------------------------------
# BUILD ALL 30 COMMERCIAL PLUGINS (.so files)
# ----------------------------------------------------
add_sentinel_plugin(sentinel_plugin_scada_modbus src/plugins/scada_modbus_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_active_deception src/plugins/active_deception_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_pcap_carver src/plugins/pcap_carver_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_dnp3_grid src/plugins/dnp3_grid_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_profinet src/plugins/profinet_inspector_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_s7comm src/plugins/s7comm_opcua_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_cef_forwarder src/plugins/cef_forwarder_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_firewall_sync src/plugins/firewall_sync_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_llm_summarizer src/plugins/llm_summarizer_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_mavlink src/plugins/mavlink_inspector_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_ais_maritime src/plugins/ais_maritime_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_rtsp_correlator src/plugins/rtsp_vision_correlator_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_gpio_siren src/plugins/gpio_siren_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_dicom_medical src/plugins/dicom_medical_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_bacnet src/plugins/bacnet_inspector_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_ad_correlator src/plugins/ad_correlator_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_webhook src/plugins/webhook_dispatcher_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_plc_decoy src/plugins/plc_decoy_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_evidence_locker src/plugins/evidence_locker_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_memory_dump src/plugins/memory_dump_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_auditd_reconstructor src/plugins/auditd_reconstructor_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_admin_portal_trap src/plugins/admin_portal_trap_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_canary_file src/plugins/canary_file_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_stanag_link16 src/plugins/stanag_link16_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_eta_traffic src/plugins/eta_traffic_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_ueba_analytics src/plugins/ueba_analytics_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_dns_tunneling src/plugins/dns_tunneling_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_onvif_tamper src/plugins/onvif_tamper_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_nmea_marine src/plugins/nmea_marine_plugin.cpp)
add_sentinel_plugin(sentinel_plugin_hl7_hospital src/plugins/hl7_hospital_plugin.cpp)

# Installation Rules
install(TARGETS 
    sentinel 
    sentinel_plugin_scada_modbus 
    sentinel_plugin_active_deception 
    sentinel_plugin_pcap_carver 
    sentinel_plugin_dnp3_grid 
    sentinel_plugin_profinet 
    sentinel_plugin_s7comm 
    sentinel_plugin_cef_forwarder 
    sentinel_plugin_firewall_sync 
    sentinel_plugin_llm_summarizer 
    sentinel_plugin_mavlink 
    sentinel_plugin_ais_maritime 
    sentinel_plugin_rtsp_correlator 
    sentinel_plugin_gpio_siren 
    sentinel_plugin_dicom_medical 
    sentinel_plugin_bacnet 
    sentinel_plugin_ad_correlator 
    sentinel_plugin_webhook 
    sentinel_plugin_plc_decoy 
    sentinel_plugin_evidence_locker 
    sentinel_plugin_memory_dump 
    sentinel_plugin_auditd_reconstructor 
    sentinel_plugin_admin_portal_trap 
    sentinel_plugin_canary_file 
    sentinel_plugin_stanag_link16 
    sentinel_plugin_eta_traffic 
    sentinel_plugin_ueba_analytics 
    sentinel_plugin_dns_tunneling 
    sentinel_plugin_onvif_tamper 
    sentinel_plugin_nmea_marine 
    sentinel_plugin_hl7_hospital 
    DESTINATION /usr/local/bin
)