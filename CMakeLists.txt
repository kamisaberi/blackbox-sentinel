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
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(BPF_LIB bpf REQUIRED)
find_library(ELF_LIB elf REQUIRED)

find_library(BLACKBOX_LIB blackbox REQUIRED PATHS /usr/local/lib /usr/lib)
find_library(XINFER_LIB xinfer REQUIRED PATHS /usr/local/lib /usr/lib)


# -------------------------------------------------------------------
# DEFINE IMPORTED GLOBAL TARGETS (FIXES THE CMAKE ERROR FOR ALL MODULES)
# -------------------------------------------------------------------
if(NOT TARGET blackbox::blackbox)
    add_library(blackbox::blackbox SHARED IMPORTED GLOBAL)
    set_target_properties(blackbox::blackbox PROPERTIES
        IMPORTED_LOCATION "${BLACKBOX_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
    )
endif()


# -------------------------------------------------------------------
# ADD THIS BLOCK FOR xinfer::xinfer
# -------------------------------------------------------------------
if(NOT TARGET xinfer::xinfer)
    add_library(xinfer::xinfer SHARED IMPORTED GLOBAL)
    set_target_properties(xinfer::xinfer PROPERTIES
        IMPORTED_LOCATION "${XINFER_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
    )
endif()

# -------------------------------------------------------------------
# ALL 26 MODULAR FEATURE TOGGLES (DEFAULT: ALL ON)
# -------------------------------------------------------------------
option(SENTINEL_ENABLE_01_SIEM          "Enable [01] SIEM Core Log Correlation"             ON)
option(SENTINEL_ENABLE_02_UEBA          "Enable [02] User & Entity Behavior Analytics"      ON)
option(SENTINEL_ENABLE_03_NDR           "Enable [03] Network Detection & Response"          ON)
option(SENTINEL_ENABLE_04_IDS_IPS       "Enable [04] Intrusion Detection & Prevention"      ON)
option(SENTINEL_ENABLE_05_WAF           "Enable [05] Web App & API Defense"                 ON)
option(SENTINEL_ENABLE_06_EDR           "Enable [06] Endpoint Detection & Response"         ON)
option(SENTINEL_ENABLE_07_EPP_NGAV      "Enable [07] Antivirus & File Entropy"              ON)
option(SENTINEL_ENABLE_08_NAC           "Enable [08] Network Access Control"                ON)
option(SENTINEL_ENABLE_09_CWPP          "Enable [09] Container eBPF Syscall Guard"          ON)
option(SENTINEL_ENABLE_10_BAD           "Enable [10] Bot & Automated Abuse Defense"         ON)
option(SENTINEL_ENABLE_11_RASP          "Enable [11] Runtime App Self-Protection"           ON)
option(SENTINEL_ENABLE_12_ITDR          "Enable [12] Identity Threat Detection & Response"  ON)
option(SENTINEL_ENABLE_13_DDOS          "Enable [13] Hardware Line-Rate DDoS Mitigation"    ON)
option(SENTINEL_ENABLE_14_ATO           "Enable [14] Account Takeover Defense"              ON)
option(SENTINEL_ENABLE_15_NGFW          "Enable [15] Next-Generation Firewall DPI"          ON)
option(SENTINEL_ENABLE_16_CDR           "Enable [16] Content Disarm & Reconstruction"       ON)
option(SENTINEL_ENABLE_17_IOT_SEC       "Enable [17] IoT & Medical Device (IoMT) Defense"   ON)
option(SENTINEL_ENABLE_18_CPS_SEC       "Enable [18] Cyber-Physical & SCADA OT Defense"     ON)
option(SENTINEL_ENABLE_19_SWG           "Enable [19] Secure Web Gateway"                    ON)
option(SENTINEL_ENABLE_20_FSE           "Enable [20] Firmware Security Evaluation"          ON)
option(SENTINEL_ENABLE_21_SIDE_CHANNEL  "Enable [21] Hardware Side-Channel Defense"         ON)
option(SENTINEL_ENABLE_22_DFIR          "Enable [22] Digital Forensics & Evidence Carver"   ON)
option(SENTINEL_ENABLE_23_AI_TRISM      "Enable [23] AI Prompt Firewall & LLM Guard"        ON)
option(SENTINEL_ENABLE_24_ZTNA          "Enable [24] Zero Trust Network Access"             ON)
option(SENTINEL_ENABLE_25_FDP           "Enable [25] Fraud Detection & Prevention"          ON)
option(SENTINEL_ENABLE_26_DDP           "Enable [26] Distributed Deception Honeypots"       ON)

set(SENTINEL_MODULE_LIBRARIES "")



macro(register_sentinel_module MODULE_OPT MODULE_DIR MODULE_TARGET)
    if(${MODULE_OPT})
        add_subdirectory(${MODULE_DIR})
        list(APPEND SENTINEL_MODULE_LIBRARIES ${MODULE_TARGET})
        add_compile_definitions(${MODULE_OPT})
    endif()
endmacro()

register_sentinel_module(SENTINEL_ENABLE_01_SIEM          src/modules/01_siem_core         sentinel_module_siem_core)
register_sentinel_module(SENTINEL_ENABLE_02_UEBA          src/modules/02_ueba              sentinel_module_ueba)
register_sentinel_module(SENTINEL_ENABLE_03_NDR           src/modules/03_ndr               sentinel_module_ndr)
register_sentinel_module(SENTINEL_ENABLE_04_IDS_IPS       src/modules/04_ids_ips           sentinel_module_ids_ips)
register_sentinel_module(SENTINEL_ENABLE_05_WAF           src/modules/05_waf               sentinel_module_waf)
register_sentinel_module(SENTINEL_ENABLE_06_EDR           src/modules/06_edr               sentinel_module_edr)
register_sentinel_module(SENTINEL_ENABLE_07_EPP_NGAV      src/modules/07_epp_ngav          sentinel_module_epp_ngav)
register_sentinel_module(SENTINEL_ENABLE_08_NAC           src/modules/08_nac               sentinel_module_nac)
register_sentinel_module(SENTINEL_ENABLE_09_CWPP          src/modules/09_cwpp              sentinel_module_cwpp)
register_sentinel_module(SENTINEL_ENABLE_10_BAD           src/modules/10_bad               sentinel_module_bad)
register_sentinel_module(SENTINEL_ENABLE_11_RASP          src/modules/11_rasp              sentinel_module_rasp)
register_sentinel_module(SENTINEL_ENABLE_12_ITDR          src/modules/12_itdr              sentinel_module_itdr)
register_sentinel_module(SENTINEL_ENABLE_13_DDOS          src/modules/13_ddos              sentinel_module_ddos)
register_sentinel_module(SENTINEL_ENABLE_14_ATO           src/modules/14_ato               sentinel_module_ato)
register_sentinel_module(SENTINEL_ENABLE_15_NGFW          src/modules/15_ngfw              sentinel_module_ngfw)
register_sentinel_module(SENTINEL_ENABLE_16_CDR           src/modules/16_cdr               sentinel_module_cdr)
register_sentinel_module(SENTINEL_ENABLE_17_IOT_SEC       src/modules/17_iot_sec           sentinel_module_iot_sec)
register_sentinel_module(SENTINEL_ENABLE_18_CPS_SEC       src/modules/18_cps_sec           sentinel_module_cps_sec)
register_sentinel_module(SENTINEL_ENABLE_19_SWG           src/modules/19_swg               sentinel_module_swg)
register_sentinel_module(SENTINEL_ENABLE_20_FSE           src/modules/20_fse               sentinel_module_fse)
register_sentinel_module(SENTINEL_ENABLE_21_SIDE_CHANNEL  src/modules/21_side_channel      sentinel_module_side_channel)
register_sentinel_module(SENTINEL_ENABLE_22_DFIR          src/modules/22_dfir              sentinel_module_dfir)
register_sentinel_module(SENTINEL_ENABLE_23_AI_TRISM      src/modules/23_ai_trism          sentinel_module_ai_trism)
register_sentinel_module(SENTINEL_ENABLE_24_ZTNA          src/modules/24_ztna              sentinel_module_ztna)
register_sentinel_module(SENTINEL_ENABLE_25_FDP           src/modules/25_fdp               sentinel_module_fdp)
register_sentinel_module(SENTINEL_ENABLE_26_DDP           src/modules/26_ddp               sentinel_module_ddp)






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
    src/core/orchestrator.cpp
    src/core/config_manager.cpp
    src/plugin_manager.cpp
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
    ${SENTINEL_MODULE_LIBRARIES}
    ${BLACKBOX_LIB}
    ${XINFER_LIB}
    ${SQLITE3_LIB}
    ${BPF_LIB}
    ${ELF_LIB}
    z
    ${CMAKE_DL_LIBS}
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


# Module Testing Executables
add_executable(test_module_ndr_ids examples/01_test_module_ndr_ids.cpp)
target_link_libraries(test_module_ndr_ids PRIVATE sentinel_module_ndr sentinel_module_ids_ips blackbox::blackbox xinfer::xinfer Threads::Threads)

add_executable(test_module_waf examples/02_test_module_waf.cpp)
target_link_libraries(test_module_waf PRIVATE sentinel_module_waf blackbox::blackbox xinfer::xinfer Threads::Threads)

add_executable(test_module_ai_trism examples/03_test_module_ai_trism.cpp)
target_link_libraries(test_module_ai_trism PRIVATE sentinel_module_ai_trism blackbox::blackbox xinfer::xinfer Threads::Threads)

add_executable(test_module_cps_scada examples/04_test_module_cps_scada.cpp)
target_link_libraries(test_module_cps_scada PRIVATE sentinel_module_cps_sec blackbox::blackbox xinfer::xinfer Threads::Threads)